"""Fast offline scoring of a corrected feature table (not a live scan)."""
import argparse
import json
from pathlib import Path
import pandas as pd
from inference.detector import Detector, IncidentGrouper


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, default=Path('models/output/improved/detector_bundle.joblib'))
    parser.add_argument('--features', type=Path, default=Path('feature_engineering/output/features_window5s_v2.parquet'))
    parser.add_argument('--output', type=Path, default=Path('inference/output/improved_scores.jsonl'))
    args = parser.parse_args()
    detector = Detector(args.bundle)
    meta = json.loads(args.features.with_suffix('.metadata.json').read_text())
    if meta['schema_version'] != detector.bundle['schema_version'] or meta['window_seconds'] != detector.seconds:
        raise ValueError('Feature metadata does not match the model')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    count = anomalies = notifications = 0
    with args.output.open('w') as output:
        for _, session in pd.read_parquet(args.features).groupby('session_id'):
            group = IncidentGrouper()
            previous_index = None
            for row in session.sort_values('window_index').to_dict('records'):
                if previous_index is not None and row['window_index'] != previous_index + 1:
                    group = IncidentGrouper()
                previous_index = row['window_index']
                scored = detector.score(row)
                output.write(json.dumps(dict(type='window', **scored)) + '\n')
                count += 1
                anomalies += int(scored['anomaly'])
                incident = group.update(scored)
                if incident:
                    output.write(json.dumps(incident) + '\n')
                    notifications += int(incident.get('notification', False))
    print(json.dumps(dict(windows=count, flagged_windows=anomalies, notifications=notifications,
                         output=str(args.output), note='Offline replay includes training/validation rows; use reserved test report for performance claims.')))


if __name__ == '__main__':
    main()
