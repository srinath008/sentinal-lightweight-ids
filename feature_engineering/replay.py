"""Stream existing CSVs through the same parser/windows as live inference."""
import argparse
import heapq
import json
from pathlib import Path
from .events import SOURCES, Window, parse_event, window_index, SCHEMA_VERSION


def event_rows(path, source, stats):
    previous = float('-inf')
    with path.open(encoding='utf-8', errors='replace') as handle:
        for line in handle:
            stats['lines'] += 1
            try:
                stamp, raw = line.rstrip().split(',', 1)
                stamp = float(stamp)
                event = parse_event(source, raw)
                if event is None:
                    stats['headers'] += 1
                    continue
                if stamp < previous:
                    raise RuntimeError(f'Non-monotonic timestamps in {path}')
                previous = stamp
                window_index(stamp, 0, 5)  # finite timestamp validation
                yield stamp, source, event
            except ValueError:
                stats['malformed'] += 1


def replay_session(directory, seconds=5.0):
    """Bound memory by one feature window; preserve all raw files."""
    directory = Path(directory)
    manifest_path = directory / 'manifest.json'
    if manifest_path.exists() and json.loads(manifest_path.read_text()).get('status') != 'complete':
        raise ValueError(f'Incomplete collection session: {directory}')
    stats = dict(lines=0, headers=0, malformed=0)
    phases = []
    phase_path = directory / 'phase_log.csv'
    if phase_path.exists():
        import csv
        with phase_path.open() as handle:
            phases = [(r['phase'], float(r['start_epoch']), float(r['end_epoch']))
                      for r in csv.DictReader(handle)]
    streams = [event_rows(directory / f'{s}.csv', s, stats) for s in SOURCES]
    origin = None
    current = 0
    window = Window()
    for stamp, source, event in heapq.merge(*streams, key=lambda item: item[0]):
        if origin is None:
            origin = stamp
        idx = window_index(stamp, origin, seconds)
        while current < idx:
            yield window.row(directory.name, current, origin, seconds), stats
            current += 1
            window = Window()
        phase = next((p for p, start, end in phases if start <= stamp <= end), 'unlabeled')
        window.add(source, event, phase)
    if origin is not None:
        yield window.row(directory.name, current, origin, seconds), stats


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--session-dir', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--window', type=float, default=5.0)
    args = parser.parse_args()
    window_index(0, 0, args.window)
    if len({directory.name for directory in args.session_dir}) != len(args.session_dir):
        raise ValueError('Session directory names must be unique')
    import pandas as pd
    rows, summaries = [], {}
    for directory in args.session_dir:
        for row, stats in replay_session(directory, args.window):
            rows.append(row)
            summaries[directory.name] = dict(stats)
        print(f'{directory.name}: {summaries.get(directory.name)}', flush=True)
    if not rows:
        raise ValueError('No valid events')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_parquet(args.output, index=False)
    args.output.with_suffix('.metadata.json').write_text(json.dumps(dict(
        schema_version=SCHEMA_VERSION, window_seconds=args.window,
        window_origin='first_valid_event_across_sources', session_stats=summaries), indent=2))


if __name__ == '__main__':
    main()
