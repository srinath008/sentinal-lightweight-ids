"""Session-separated training, baseline validation calibration, held-out evaluation."""
import argparse
import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score
from feature_engineering.events import FEATURES, SCHEMA_VERSION
from models.incident_metrics import incident_metrics


def split_sessions(frame, train, validation, test):
    groups = [set(train), set(validation), set(test)]
    if any(not group for group in groups) or any(groups[i] & groups[j] for i in range(3) for j in range(i)):
        raise ValueError('Train, validation, and test require nonempty disjoint session IDs')
    missing = set.union(*groups) - set(frame.session_id)
    if missing:
        raise ValueError(f'Missing sessions: {sorted(missing)}')
    parts = [frame[frame.session_id.isin(group)].copy() for group in groups]
    if any(not (part.phase == 'baseline').any() for part in parts):
        raise ValueError('Each partition needs baseline windows')
    if not parts[2].phase.str.startswith('attack_').any():
        raise ValueError('Test sessions need simulated attack windows')
    return parts


def calibrate(scores, target_fpr):
    """Strict score < threshold; empirical baseline FPR does not exceed target."""
    if not 0 <= target_fpr < 1:
        raise ValueError('target_fpr must be in [0, 1)')
    scores = np.sort(np.asarray(scores, dtype=float))
    if not len(scores) or not np.isfinite(scores).all():
        raise ValueError('Calibration needs finite baseline scores')
    return float(scores[int(np.floor(target_fpr * len(scores)))])


def metrics(frame, scores, threshold, seconds):
    mask = (frame.phase == 'baseline') | frame.phase.str.startswith('attack_')
    sub, values = frame[mask], np.asarray(scores)[mask]
    truth = sub.phase.str.startswith('attack_').to_numpy()
    pred = values < threshold
    baseline = ~truth
    false = int(pred[baseline].sum())
    return dict(windows=len(sub), excluded_windows=int((~mask).sum()),
                true_positives=int((truth & pred).sum()), false_negatives=int((truth & ~pred).sum()),
                false_positives=false, true_negatives=int((baseline & ~pred).sum()),
                precision=float(precision_score(truth, pred, zero_division=0)),
                recall=float(recall_score(truth, pred, zero_division=0)),
                f1=float(f1_score(truth, pred, zero_division=0)),
                roc_auc=float(roc_auc_score(truth, -values)) if len(set(truth)) == 2 else None,
                baseline_false_positive_rate=false / int(baseline.sum()),
                flagged_baseline_windows_per_hour=false * 3600 / (int(baseline.sum()) * seconds),
                per_phase={phase: float(pred[(sub.phase == phase).to_numpy()].mean()) for phase in sub.phase.unique()})


def train(args):
    metadata = json.loads(args.features.with_suffix('.metadata.json').read_text())
    if metadata['schema_version'] != SCHEMA_VERSION:
        raise ValueError('Rebuild features using the corrected pipeline')
    seconds = metadata['window_seconds']
    if not np.isfinite(seconds) or seconds <= 0:
        raise ValueError('Invalid feature window duration')
    frame = pd.read_parquet(args.features)
    if not np.isfinite(frame[FEATURES].to_numpy(dtype=float)).all():
        raise ValueError('Non-finite feature values')
    training, validation, testing = split_sessions(frame, args.train, args.validation, args.test)
    normal = training.loc[training.phase == 'baseline', FEATURES].to_numpy(dtype=float)
    valid = validation.loc[validation.phase == 'baseline', FEATURES].to_numpy(dtype=float)
    if len(normal) < 50 or len(valid) < 50:
        raise ValueError('At least 50 baseline windows required for training and validation')
    scaler = StandardScaler().fit(normal)
    detectors = dict(isolation_forest=IsolationForest(n_estimators=200, random_state=42, n_jobs=-1).fit(normal),
                     ocsvm=OneClassSVM(nu=.05, gamma='scale').fit(scaler.transform(normal)))
    bundle = dict(schema_version=SCHEMA_VERSION, features=FEATURES, window_seconds=seconds,
                  transformations={'n_open': 'log1p(n_open_raw)', 'n_unique_paths': 'log1p(n_unique_paths_raw)'},
                  window_origin=metadata['window_origin'], sklearn_version=sklearn.__version__,
                  scaler=scaler, models=detectors, thresholds={})
    report = dict(train_sessions=args.train, validation_sessions=args.validation,
                  test_sessions=args.test, target_validation_fpr=args.target_fpr,
                  sklearn_version=sklearn.__version__, window_seconds=seconds,
                  note='Simulated behaviours; no general virus-detection claim.', models={})
    for name, model in detectors.items():
        score = lambda x: model.score_samples(x) if name == 'isolation_forest' else model.decision_function(scaler.transform(x))
        threshold = calibrate(score(valid), args.target_fpr)
        bundle['thresholds'][name] = threshold
        values = score(testing[FEATURES].to_numpy(dtype=float))
        report['models'][name] = dict(threshold=threshold,
            validation_baseline_fpr=float((score(valid) < threshold).mean()),
            test=metrics(testing, values, threshold, seconds),
            incidents=incident_metrics(testing, values, threshold, seconds))
    args.output.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, args.output / 'detector_bundle.joblib')
    (args.output / 'validation_report.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--features', type=Path, required=True)
    for name in ('train', 'validation', 'test'):
        parser.add_argument('--' + name, nargs='+', required=True)
    parser.add_argument('--target-fpr', type=float, default=.01)
    parser.add_argument('--output', type=Path, default=Path('models/output/validated'))
    train(parser.parse_args())


if __name__ == '__main__':
    main()
