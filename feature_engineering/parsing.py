"""DataFrame compatibility loaders using the shared live/replay parser.

For large sessions use feature_engineering.replay instead of allocating rows.
Rejected/header counts are available in DataFrame.attrs['parse_stats'].
"""
from pathlib import Path
import pandas as pd
from feature_engineering.events import parse_event, window_index

SCHEMAS = {
    'execsnoop': (['timestamp', 'pcomm', 'pid', 'ppid', 'ret', 'args'], ['pid', 'ppid', 'ret']),
    'opensnoop': (['timestamp', 'pid', 'comm', 'fd', 'err', 'path'], ['pid', 'fd', 'err']),
    'tcpconnect': (['timestamp', 'pid', 'comm', 'ip', 'saddr', 'daddr', 'dport'], ['pid', 'ip', 'dport']),
}


def _load(path, source):
    rows = []
    stats = dict(lines=0, headers=0, malformed=0)
    with Path(path).open(encoding='utf-8', errors='replace') as handle:
        for line in handle:
            stats['lines'] += 1
            try:
                stamp, raw = line.strip().split(',', 1)
                stamp = float(stamp)
                window_index(stamp, 0, 5)
                event = parse_event(source, raw)
                if event is None:
                    stats['headers'] += 1
                else:
                    rows.append(dict(timestamp=stamp, **event))
            except ValueError:
                stats['malformed'] += 1
    columns, numeric = SCHEMAS[source]
    frame = pd.DataFrame(rows, columns=columns)
    frame['timestamp'] = frame['timestamp'].astype(float)
    for column in numeric:
        frame[column] = frame[column].astype('Int64')
    frame.attrs['parse_stats'] = stats
    return frame


def load_execsnoop(path):
    return _load(path, 'execsnoop')


def load_opensnoop(path):
    return _load(path, 'opensnoop')


def load_tcpconnect(path):
    return _load(path, 'tcpconnect')
