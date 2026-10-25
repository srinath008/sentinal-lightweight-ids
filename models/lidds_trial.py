"""Diagnostic augmentation trial; container-derived views cannot promote a bundle.

Use frozen selected SVM settings, native partitions, and a single predeclared
augmentation of half the native training count. No hyperparameter search.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import joblib
import pandas as pd
from feature_engineering.events import FEATURES
from models.improve_existing import blocked_split
from models.validated_training import calibrate, metrics


def passes(before, after):
    phases = [k for k in before['per_phase'] if k.startswith('attack_')]
    return (after['false_positives'] < before['false_positives']
            and after['recall'] >= before['recall']
            and all(after['per_phase'][k] >= max(.95, before['per_phase'][k]) for k in phases))


def evaluate(frame, scores, threshold):
    result = metrics(frame, scores, threshold, 5.)
    if result['true_positives'] + result['false_negatives'] == 0:
        # Normal-only validation cannot measure attack detection.
        result.update(recall=None, precision=None, f1=None)
    return result


def run(native_path, external_path, audit_path, bundle_path, output, report_path=None):
    native = pd.read_parquet(native_path)
    external = pd.read_parquet(external_path)
    audit = json.loads(audit_path.read_text(encoding='utf-8'))
    excluded = [record['session_id'] for record in audit['records']
                if any(record['stats'].get(key, 0) for key in
                       ('malformed', 'unresolved_feature_events', 'connect_unknown_protocol'))]
    # An unresolved event invalidates its entire recording, not just that row.
    external = external[~external.session_id.isin(excluded)].copy()
    if external.empty:
        raise ValueError('No fully parseable external recordings; do not invent missing values')
    parts, manifest = blocked_split(native)
    training = parts['train'].query('phase == "baseline"')
    external_train = external.query('partition == "training" and phase == "baseline"')
    # Avoid loading this scenario with disproportionate weight into a tiny native dataset.
    count = min(len(external_train), len(training)//2)
    if count == 0:
        raise ValueError('No eligible external baseline windows')
    addition = external_train.sample(n=count, random_state=2026).sort_index()
    reference_bundle = joblib.load(bundle_path)
    reference = reference_bundle['pipeline']
    candidate = copy.deepcopy(reference)
    candidate.fit(pd.concat([training, addition])[FEATURES].to_numpy(float))
    validation = parts['validation']
    normal = validation.phase.eq('baseline').to_numpy()
    original_threshold = reference_bundle['threshold']
    threshold = calibrate(candidate.score_samples(validation[FEATURES].to_numpy(float))[normal], .01)
    output.mkdir(parents=True, exist_ok=True)
    frozen = dict(augmentation_windows=count, seed=2026, model_settings='Previously selected SVM gamma=.1 nu=.02',
                  calibration='Native normal validation only; 1% target, same as reference',
                  candidate_threshold=threshold, original_threshold=original_threshold,
                  native_split=manifest, external_recording_partitions='Official partitions preserved',
                  certification='Diagnostic container-derived features; not native-compatible',
                  promotion_allowed=False)
    (output / 'frozen_before_test.json').write_text(json.dumps(frozen, indent=2), encoding='utf-8')
    results = {}
    for name, frame in [('native_validation', validation), ('native_test', parts['test']),
                        ('external_validation', external.query('partition == "validation"')),
                        ('external_test', external.query('partition == "test"'))]:
        values = frame[FEATURES].to_numpy(float)
        results[name] = dict(native_only=evaluate(frame, reference.score_samples(values), original_threshold),
                             augmented=evaluate(frame, candidate.score_samples(values), threshold))
    summary = dict(protocol=frozen, dataset_sha256=audit['sha256'],
                   current_bundle_sha256=hashlib.file_digest(bundle_path.open('rb'),'sha256').hexdigest(),
                   native_training_windows=len(training), eligible_external_training_windows=len(external_train),
                   excluded_external_recordings=excluded,
                   external_training_records=int(external_train.session_id.nunique()),
                   added_training_records=int(addition.session_id.nunique()),
                   native_validation_gate=passes(**dict(before=results['native_validation']['native_only'],
                                                       after=results['native_validation']['augmented'])),
                   native_test_gate=passes(results['native_test']['native_only'], results['native_test']['augmented']),
                   results=results, promoted=False,
                   normal_feature_medians={
                       'native_training': training[FEATURES + ['n_open_raw']].median().to_dict(),
                       'external_training': external_train[FEATURES + ['n_open_raw']].median().to_dict()},
                   limitations=audit['limitations'] + ['External attack_exposure means time after onset, not per-window malicious ground truth',
                                                     'Native test blocks were historically examined; only external recordings are new to this project',
                                                     'Window sampling is training-only; external evaluation keeps complete retained recordings',
                                                     '1% native validation quantile usually fixes FP count; strict improvement gate can fail by design'])
    for name, model, cutoff in [('native_only',reference,original_threshold),('augmented',candidate,threshold)]:
        by_profile = {}
        for sid, group in parts['test'].groupby('session_id'):
            by_profile[sid] = metrics(group, model.score_samples(group[FEATURES].to_numpy(float)), cutoff, 5.)
        summary.setdefault('native_test_per_profile',{})[name] = by_profile
    attack_view = external.query('partition == "test" and phase == "attack_exposure"')
    normal_support = set(map(tuple, external_train[FEATURES].to_numpy()))
    summary['feature_overlap'] = dict(
        constant_features=[name for name in FEATURES if external[name].nunique() == 1],
        attack_exposure_windows_in_normal_training_support=sum(
            tuple(row) in normal_support for row in attack_view[FEATURES].to_numpy()),
        attack_exposure_windows=len(attack_view),
        attack_recordings_with_retained_exposure=int(attack_view.session_id.nunique()))
    (output / 'results.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    if report_path is not None:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(summary,indent=2),encoding='utf-8')
    # Save only the diagnostic estimator, never a deployable/native metadata bundle.
    joblib.dump(dict(estimator=candidate,threshold=threshold,certified_native_compatible=False),
                output / 'diagnostic_estimator.joblib')
    print(json.dumps({k:v for k,v in summary.items() if k not in ('protocol','native_test_per_profile')},indent=2))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native',type=Path,default=Path('feature_engineering/output/features_window5s_v2.parquet'))
    parser.add_argument('--external',type=Path,default=Path('external_data/lidds/audit/diagnostic_features.parquet'))
    parser.add_argument('--audit',type=Path,default=Path('external_data/lidds/audit/audit.json'))
    parser.add_argument('--bundle',type=Path,default=Path('models/output/improved/detector_bundle.joblib'))
    parser.add_argument('--output',type=Path,default=Path('external_data/lidds/trial'))
    parser.add_argument('--report',type=Path,default=Path('docs/LIDDS_TRIAL_RESULTS.json'))
    args=parser.parse_args()
    run(args.native,args.external,args.audit,args.bundle,args.output,args.report)


if __name__ == '__main__':
    main()
