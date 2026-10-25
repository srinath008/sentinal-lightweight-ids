"""Stress-test frozen model settings on the OTHER preserved session.

Neither session is new to this project. This checks workload transfer, not
independent prospective performance, and must not be used to retune settings.
"""
import argparse
import json
from pathlib import Path
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler
from sklearn.svm import OneClassSVM
from feature_engineering.events import FEATURES
from feature_engineering.model_features import behavioural_features
from models.validated_training import calibrate, metrics


def evaluate(frame):
    sessions = sorted(frame.session_id.unique())
    if len(sessions) < 2:
        raise ValueError('Need at least two sessions')
    results = []
    for sid in sessions:
        baseline = frame[(frame.session_id == sid) & (frame.phase == 'baseline')].sort_values('window_index')
        split = int(len(baseline) * .75)
        train, validation = baseline.iloc[:split-2], baseline.iloc[split+2:]
        if train.empty or validation.empty:
            raise ValueError('Insufficient baseline for calibration with embargo')
        for name, estimator in [
            ('selected_ocsvm', make_pipeline(FunctionTransformer(behavioural_features), StandardScaler(),
                                            OneClassSVM(gamma=.1, nu=.02))),
            ('reference_if', IsolationForest(n_estimators=200, random_state=42, n_jobs=-1))]:
            estimator.fit(train[FEATURES].to_numpy(float))
            threshold = calibrate(estimator.score_samples(validation[FEATURES].to_numpy(float)), .01)
            for target in sessions:
                if target == sid:
                    continue
                test = frame[frame.session_id == target].sort_values('window_index')
                scores = estimator.score_samples(test[FEATURES].to_numpy(float))
                results.append(dict(model=name, training_session=sid, test_session=target,
                                    training_baseline_windows=len(train), calibration_baseline_windows=len(validation),
                                    threshold=threshold, metrics=metrics(test, scores, threshold, 5.)))
    return dict(note='Frozen settings; historically examined sessions; no new independent data. '
                     'Checks transfer between idle and media workloads. No model promotion or retuning.', results=results)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--features', type=Path, default=Path('feature_engineering/output/features_window5s_v2.parquet'))
    parser.add_argument('--output', type=Path, default=Path('docs/WORKLOAD_TRANSFER_RESULTS.json'))
    args = parser.parse_args()
    result = evaluate(pd.read_parquet(args.features))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    for row in result['results']:
        print(row['model'], row['training_session'], '->', row['test_session'], row['metrics'])


if __name__ == '__main__':
    main()
