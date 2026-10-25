"""Evaluate frozen SVM cutoffs against WSL diagnostics and historical attacks.

This diagnostic never writes a model artifact or changes production settings.
"""
import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd
from inference.detector import Detector
from feature_engineering.events import FEATURES
from models.validated_training import calibrate, metrics


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--diagnostics',type=Path,default=Path('docs/WSL_LIVE_DIAGNOSTICS.json'))
    parser.add_argument('--previous-report',type=Path,default=Path('.test-output/previous-live-report.json'))
    parser.add_argument('--output',type=Path,default=Path('docs/WSL_CALIBRATION_RESULTS.json'))
    args=parser.parse_args()
    artifact=Path('models/output/improved/detector_bundle.joblib')
    detector=Detector(artifact)
    pipeline=detector.bundle['pipeline']
    diagnostics=json.loads(args.diagnostics.read_text())
    previous=json.loads(args.previous_report.read_text())['session']['windows']
    historical=pd.DataFrame(json.loads(line) for line in Path('desktop/replay.jsonl').read_text().splitlines())

    def scores(rows):
        return pipeline.score_samples(pd.DataFrame(rows)[FEATURES].to_numpy(float))

    historical_scores=scores(historical)
    previous_scores=scores(previous)
    phases={phase['label']:phase for phase in diagnostics['phases']}
    live_scores={name:scores(phase['windows']) for name,phase in phases.items()}
    cutoffs=dict(installed=detector.bundle['threshold'],
        previous_first_25_assumed_normal=calibrate(previous_scores[:25],.01),
        short_app_open_normal=calibrate(live_scores['app_open_idle'],.01))
    results={}
    for name,cutoff in cutoffs.items():
        results[name]=dict(threshold=cutoff,
            historical_reserved=metrics(historical,historical_scores,cutoff,5),
            previous_later_26_assumed_normal=dict(windows=len(previous_scores[25:]),
                flagged=int((previous_scores[25:]<cutoff).sum())),
            diagnostic_phases={label:dict(windows=len(values),flagged=int((values<cutoff).sum()),
                flagged_fraction=float((values<cutoff).mean()),min_score=float(values.min()),max_score=float(values.max()))
                for label,values in live_scores.items()})
    normal_vectors=np.vstack([pd.DataFrame(p['windows'])[FEATURES].to_numpy(float)
                             for label,p in phases.items() if 'idle' in label])
    # Compare input ranges to historical training baseline; not a proof of cause.
    from models.improve_existing import blocked_split
    full=pd.read_parquet('feature_engineering/output/features_window5s_v2.parquet')
    parts,_=blocked_split(full)
    train=parts['train'].query('phase == "baseline"')
    ranges={feature:dict(historical_baseline_min=float(train[feature].min()),
        historical_baseline_max=float(train[feature].max()),wsl_idle_min=float(normal_vectors[:,i].min()),
        wsl_idle_max=float(normal_vectors[:,i].max())) for i,feature in enumerate(FEATURES)}
    report=dict(model_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
        protocol='Frozen model; two exploratory lower cutoffs calibrated separately from later WSL windows. No parameter or artifact promotion.',
        limitations=['Short sequential benign diagnostics on one WSL host; not malware accuracy validation.',
            'The previous 51-window session has no ground-truth labels; its first 25 are assumed normal only for a sensitivity experiment.',
            'Historical 600 windows have previously been examined and are regression evidence, not a new independent test.',
            'The short app-open calibration has very few windows; zero observed false alerts would not establish a reliable population rate.'],
        feature_ranges=ranges,comparisons=results)
    args.output.write_text(json.dumps(report,indent=2))
    print(json.dumps({name:dict(historical_recall=result['historical_reserved']['recall'],
        historical_fpr=result['historical_reserved']['baseline_false_positive_rate'],
        wsl_holdout=result['diagnostic_phases']['app_open_idle_holdout']) for name,result in results.items()},indent=2))


if __name__=='__main__': main()
