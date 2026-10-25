"""Score saved logs with the validated model and incident policy (not live)."""
import argparse
import json
from pathlib import Path
from feature_engineering.replay import replay_session
from inference.detector import Detector, IncidentGrouper


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--session-dir', type=Path, required=True)
    parser.add_argument('--consecutive', type=int, default=2)
    parser.add_argument('--cooldown', type=float, default=60)
    args = parser.parse_args()
    detector = Detector(args.bundle)
    grouper = IncidentGrouper(args.consecutive, args.cooldown)
    stats = dict(lines=0, headers=0, malformed=0)
    for row, stats in replay_session(args.session_dir, detector.seconds):
        scored = detector.score(row)
        print(json.dumps(dict(type='window', **scored)), flush=True)
        incident = grouper.update(scored)
        if incident:
            print(json.dumps(incident), flush=True)
    print(json.dumps(dict(type='replay_complete', **stats)), flush=True)


if __name__ == '__main__':
    main()
