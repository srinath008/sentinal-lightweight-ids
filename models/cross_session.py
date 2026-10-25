"""Exploratory fixed-threshold holdout checks; not a final calibrated evaluation."""
import argparse
import json
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from feature_engineering.events import FEATURES
from models.validated_training import metrics
from models.incident_metrics import incident_metrics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--features', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    meta = json.loads(args.features.with_suffix('.metadata.json').read_text())
    frame = pd.read_parquet(args.features)
    report = dict(note='Exploratory leave-one-session-out; fixed default thresholds; not final validation.', folds=[])
    for sid in sorted(frame.session_id.unique()):
        training = frame[(frame.session_id != sid) & (frame.phase == 'baseline')]
        test = frame[frame.session_id == sid]
        if training.empty:
            raise ValueError('At least two sessions needed')
        normal = training[FEATURES].to_numpy(dtype=float)
        scaler = StandardScaler().fit(normal)
        forest = IsolationForest(n_estimators=200, random_state=42, n_jobs=-1).fit(normal)
        svm = OneClassSVM(nu=.05).fit(scaler.transform(normal))
        vectors = test[FEATURES].to_numpy(dtype=float)
        forest_scores = forest.score_samples(vectors)
        report['folds'].append(dict(test_session=sid,
            training_sessions=sorted(training.session_id.unique().tolist()),
            isolation_forest=metrics(test, forest_scores, -.5, meta['window_seconds']),
            isolation_forest_incidents=incident_metrics(test, forest_scores, -.5, meta['window_seconds']),
            ocsvm=metrics(test, svm.decision_function(scaler.transform(vectors)), 0, meta['window_seconds'])))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
