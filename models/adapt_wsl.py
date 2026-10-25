"""Explore host adaptation without changing the installed detector.

Select with validation only, then freeze selection before evaluating test
sessions. Historical simulations are not real-malware evidence.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import time

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier, IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler
from sklearn.svm import OneClassSVM
from threadpoolctl import threadpool_limits

from feature_engineering.events import FEATURES, SCHEMA_VERSION
from feature_engineering.model_features import behavioural_features
from models.improve_existing import blocked_split, normal_scores
from models.validated_training import calibrate, metrics
from models.incident_metrics import incident_metrics
from inference.profile_union import NormalProfileUnion


def read_sessions(directory):
    manifest=json.loads((directory/'manifest.json').read_text())
    if manifest['status']!='complete': raise ValueError('Collection must finish before model selection')
    rows=[]
    for session in manifest['sessions']:
        captured=json.loads((directory/(session['session_id']+'.json')).read_text())
        windows=[row for row in captured if 'window_index' in row]
        # Drop two windows at each end, including tracer/workload startup.
        for row in windows[2:-2]:
            row['session_id']=directory.name+':'+row['session_id']
            rows.append(row)
    frame=pd.DataFrame(rows)
    if not np.isfinite(frame[FEATURES].to_numpy(float)).all(): raise ValueError('Invalid features')
    partitions={key:frame[frame.partition.eq(key)].copy() for key in ('train','validation','test')}
    if any(len(part)==0 for part in partitions.values()): raise ValueError('Missing partition')
    if any(set(partitions[a].session_id)&set(partitions[b].session_id)
           for a,b in [('train','validation'),('train','test'),('validation','test')]):
        raise ValueError('Session overlap')
    return partitions,manifest


def candidates():
    transform=lambda:FunctionTransformer(behavioural_features)
    for gamma in (.001,.01,.1,1):
        for nu in (.01,.05):
            yield f'svm_g{gamma}_nu{nu}','unsupervised',make_pipeline(transform(),StandardScaler(),OneClassSVM(gamma=gamma,nu=nu))
    for samples in (128,256,512):
        yield f'if_log_{samples}','unsupervised',make_pipeline(transform(),IsolationForest(n_estimators=160,max_samples=samples,random_state=42,n_jobs=2))
    for neighbors in (10,30,60):
        yield f'lof_{neighbors}','unsupervised',make_pipeline(transform(),StandardScaler(),LocalOutlierFactor(n_neighbors=neighbors,novelty=True,n_jobs=2))
    for leaf in (2,5,10):
        yield f'extratrees_{leaf}','supervised_known_simulations',make_pipeline(transform(),ExtraTreesClassifier(n_estimators=160,min_samples_leaf=leaf,class_weight='balanced',random_state=42,n_jobs=2))
    yield 'hist_gradient','supervised_known_simulations',make_pipeline(transform(),HistGradientBoostingClassifier(max_iter=120,max_leaf_nodes=15,l2_regularization=1,random_state=42))


def wsl_metrics(frame,values,cutoff):
    output={}
    for workload in frame.workload.unique():
        mask=frame.workload.eq(workload).to_numpy()
        output[workload]=dict(windows=int(mask.sum()),flagged=int((values[mask]<cutoff).sum()),
                             flagged_fraction=float((values[mask]<cutoff).mean()))
    return output


def qualifies(result):
    native=result['historical_validation']
    recalls=[rate for phase,rate in native['per_phase'].items() if phase.startswith('attack_')]
    return min(recalls)>=.95 and native['baseline_false_positive_rate']<=.02 and max(
        group['flagged_fraction'] for group in result['wsl_validation'].values())<=.05


def selection_key(result):
    recalls=[rate for phase,rate in result['historical_validation']['per_phase'].items() if phase.startswith('attack_')]
    fpr=max(group['flagged_fraction'] for group in result['wsl_validation'].values())
    mean_fpr=np.mean([group['flagged_fraction'] for group in result['wsl_validation'].values()])
    return (qualifies(result),result.get('preserves_reference_normal',False),min(recalls)-fpr,-mean_fpr,result['family']=='unsupervised',-result['artifact_bytes'])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sessions',type=Path,default=Path('.test-output/wsl-adaptation-20261017'))
    parser.add_argument('--output',type=Path,default=Path('.test-output/wsl-adapted-models'))
    parser.add_argument('--report',type=Path,default=Path('docs/WSL_ADAPTATION_RESULTS.json'))
    parser.add_argument('--normal-only',action='store_true',help='Compare normal-only novelty detectors after the first supervised model failed new probes')
    parser.add_argument('--previous-sessions',type=Path,help='Add earlier train/validation partitions only; earlier test rows remain excluded')
    parser.add_argument('--development-normal',action='store_true',help='Use earlier diagnostics as explicitly assumed-normal development data; fresh follow-up sessions remain separate')
    parser.add_argument('--development-sessions',type=Path,help='Explicit adaptive-development reuse of earlier normal test rows; never stress probes. Requires fresh final sessions.')
    parser.add_argument('--local-target-fpr',type=float,default=.05)
    args=parser.parse_args()
    if not 0<=args.local_target_fpr<1:parser.error('Local false-alert target must be in [0,1)')
    args.output.mkdir(parents=True,exist_ok=False)
    local,manifest=read_sessions(args.sessions)
    if args.previous_sessions:
        earlier,_=read_sessions(args.previous_sessions)
        for part in ('train','validation'):
            local[part]=pd.concat([earlier[part],local[part]],ignore_index=True)
    development_sources=[]
    if args.development_sessions:
        development,_=read_sessions(args.development_sessions)
        normals=development['test'].query('phase == "baseline"').copy()
        normals['partition']='train'
        local['train']=pd.concat([local['train'],normals],ignore_index=True)
        development_sources.append('Normal test rows from '+str(args.development_sessions)+' explicitly reused as development training; not claimed held out in this round. Stress probes excluded.')
    if args.development_normal:
        extra=[]
        path=Path('.test-output/previous-live-report.json')
        if path.exists():
            captured=json.loads(path.read_text())['session']['windows'][:25]
            for row in captured:
                extra.append(dict(row,session_id='development_earlier_user_first25',partition='train',workload='earlier_assumed_normal',phase='baseline'))
            development_sources.append('First 25 earlier user windows assumed normal; later 26 are not fitted and remain retrospective audit only.')
        path=Path('docs/WSL_LIVE_DIAGNOSTICS.json')
        if path.exists():
            for phase in json.loads(path.read_text())['phases']:
                if 'idle' in phase['label']:
                    for row in phase['windows']:
                        extra.append(dict(row,session_id='development_'+phase['label'],partition='train',workload=phase['label'],phase='baseline'))
            development_sources.append('Earlier requested-idle diagnostics, including observed automatic-update activity; development baseline, not independent test.')
        if extra:local['train']=pd.concat([local['train'],pd.DataFrame(extra)],ignore_index=True)
    historical,_=blocked_split(pd.read_parquet('feature_engineering/output/features_window5s_v2.parquet'))
    base=historical['train']
    wsl_train=local['train']
    # Balance host domains in training only; duplicates never cross partitions.
    repeats=max(1,int(base.phase.eq('baseline').sum()/len(wsl_train)))
    augmented=pd.concat([base,*([wsl_train]*repeats)],ignore_index=True)
    values=augmented[FEATURES].to_numpy(float)
    labels=augmented.phase.str.startswith('attack_').to_numpy(int)
    old_valid=historical['validation'];new_valid=local['validation']
    valid_values=old_valid[FEATURES].to_numpy(float);new_valid_values=new_valid[FEATURES].to_numpy(float)
    records=[];trained={}
    candidate_list=list(candidates())
    if args.normal_only:
        reference_bundle=joblib.load('models/output/improved/detector_bundle.joblib')
        for gamma in (.01,.1,1.):
            candidate_list.append((f'profile_union_g{gamma}','unsupervised',NormalProfileUnion(
                reference_bundle['pipeline'],reference_bundle['threshold'],wsl_train[FEATURES].to_numpy(float),
                new_valid_values,gamma=gamma,nu=.01,target_fpr=args.local_target_fpr)))
    with threadpool_limits(limits=2):
        for name,family,model in candidate_list:
            if args.normal_only and family!='unsupervised':
                continue
            started=time.perf_counter()
            if family=='unsupervised':model.fit(values[labels==0])
            else:model.fit(values,labels)
            old_scores=normal_scores(model,family,valid_values)
            new_scores=normal_scores(model,family,new_valid_values)
            cutoffs=[calibrate(old_scores[old_valid.phase.eq('baseline')],.01)]
            cutoffs.extend(calibrate(new_scores[new_valid.workload.eq(kind)],args.local_target_fpr) for kind in new_valid.workload.unique())
            cutoff=min(cutoffs)
            if isinstance(model,NormalProfileUnion):cutoff=min(cutoff,1.)
            buffer=io.BytesIO();joblib.dump(model,buffer)
            result=dict(name=name,family=family,threshold=cutoff,artifact_bytes=buffer.tell(),
                preserves_reference_normal=isinstance(model,NormalProfileUnion) and cutoff<=1.,
                training_seconds=time.perf_counter()-started,
                historical_validation=metrics(old_valid,old_scores,cutoff,5),
                wsl_validation=wsl_metrics(new_valid,new_scores,cutoff))
            records.append(result);trained[name]=model
            print(json.dumps(dict(name=name,qualifies=qualifies(result),
                recall=result['historical_validation']['recall'],wsl=result['wsl_validation'])),flush=True)
        selected=max(records,key=selection_key)
        selection=dict(selected=selected,candidates=records,local_target_fpr=args.local_target_fpr,rule='>=95% validation recall in each historical attack phase, <=2% historical baseline flags and <=5% WSL normal flags per workload; prefer qualified models that preserve reference normal acceptance, then maximize worst recall minus worst WSL flag rate, then minimize mean WSL flags, then prefer smaller unsupervised model.',
            partition_counts={part:len(frame) for part,frame in local.items()},wsl_training_repeats=repeats)
        (args.output/'selection_before_test.json').write_text(json.dumps(selection,indent=2))
        model=trained[selected['name']];family=selected['family'];cutoff=selected['threshold']
        old_test=historical['test'];new_test=local['test']
        old_scores=normal_scores(model,family,old_test[FEATURES].to_numpy(float))
        new_scores=normal_scores(model,family,new_test[FEATURES].to_numpy(float))
        original=joblib.load('models/output/improved/detector_bundle.joblib')
        ref_old=normal_scores(original['pipeline'],original['family'],old_test[FEATURES].to_numpy(float))
        ref_new=normal_scores(original['pipeline'],original['family'],new_test[FEATURES].to_numpy(float))
        test=dict(historical=metrics(old_test,old_scores,cutoff,5),
            historical_incidents=incident_metrics(old_test,old_scores,cutoff,5),wsl=wsl_metrics(new_test,new_scores,cutoff))
        reference=dict(historical=metrics(old_test,ref_old,original['threshold'],5),
            wsl=wsl_metrics(new_test,ref_new,original['threshold']))
        earlier_path=Path('.test-output/previous-live-report.json')
        earlier_audit=None
        if earlier_path.exists():
            earlier=pd.DataFrame(json.loads(earlier_path.read_text())['session']['windows'])
            audit_scores=normal_scores(model,family,earlier[FEATURES].to_numpy(float))
            earlier_audit=dict(windows=len(earlier),flagged=int((audit_scores<cutoff).sum()),
                fitted_prefix_windows=25 if args.development_normal else 0,
                later_unfitted_windows=len(earlier.iloc[25:]),later_unfitted_flagged=int((audit_scores[25:]<cutoff).sum()),
                limitation='Earlier user session has no verified ground-truth labels. When development-normal is enabled its first 25 windows are fitted; later windows are retrospective audit only, not a fresh test.')
        recalls=[value for phase,value in test['historical']['per_phase'].items() if phase.startswith('attack_')]
        normal=[value['flagged_fraction'] for kind,value in test['wsl'].items() if kind in ('idle','benign')]
        probes=[value['flagged_fraction'] for kind,value in test['wsl'].items() if kind.startswith('probe_')]
        gates=dict(validation=qualifies(selected),historical_each_phase_recall=min(recalls)>=.95,
            historical_baseline_fpr=test['historical']['baseline_false_positive_rate']<=.03,
            wsl_each_normal_profile_fpr=max(normal)<=.05,each_stress_probe_flag_rate=min(probes)>=.8)
        bundle={key:value for key,value in original.items() if key!='pipeline'}
        bundle.update(primary_name=selected['name'],family=family,pipeline=model,threshold=cutoff,
            sklearn_version=sklearn.__version__,evaluation_scope='Local WSL adaptation preview: chronological within-host normal sessions plus historical synthetic attack blocks and harmless stress probes',
            adaptation_gates=gates,evaluation_summary=test['historical'],
            local_evaluation=test['wsl'],display_name=('Profile union SVM' if selected['name'].startswith('profile_union') else
                'Extra Trees' if selected['name'].startswith('extratrees') else
                'One-Class SVM' if selected['name'].startswith('svm') else
                'Isolation Forest' if selected['name'].startswith('if_') else
                'Local Outlier Factor' if selected['name'].startswith('lof') else 'Gradient Boosting'))
        path=args.output/'candidate_bundle.joblib';joblib.dump(bundle,path)
        timings=[]
        for _ in range(50):
            start=time.perf_counter();normal_scores(model,family,new_test[FEATURES].to_numpy(float)[:1]);timings.append(time.perf_counter()-start)
    report=dict(selection=selection,test=test,reference=reference,gates=gates,all_gates_pass=all(gates.values()),
        artifact=dict(path=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),bytes=path.stat().st_size,prediction_p95_ms=float(np.quantile(timings,.95)*1000)),
        manifest=manifest,normal_only=args.normal_only,previous_training_sessions=str(args.previous_sessions) if args.previous_sessions else None,
        development_sources=development_sources,previous_session_audit=earlier_audit,limitations=['One WSL host and short sequential sessions, not representative user browsing or an independent machine.',
            'Historical attack data are previously examined scripted simulations, not real malware.',
            'Stress probes are harmless unusual workloads; detecting them does not prove malicious intent.',
            'Model selection is frozen before this run uses test scores. No candidate is automatically installed.'])
    args.report.write_text(json.dumps(report,indent=2));print(json.dumps(dict(selected=selected['name'],gates=gates,test=test['wsl']),indent=2))


if __name__=='__main__': main()
