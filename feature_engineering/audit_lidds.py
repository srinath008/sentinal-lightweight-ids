"""Inspect LID-DS 2021 .sc recordings without treating them as native data.

Format reference: LID-DS/LID-DS dataloader/syscall_2021.py.
This audits field availability only; it does not certify semantic equivalence.
"""
import argparse
from collections import Counter
from contextlib import contextmanager
import io
import json
from pathlib import Path
import zipfile


@contextmanager
def recording_lines(path):
    path = Path(path)
    if path.suffix.lower() == '.zip':
        with zipfile.ZipFile(path) as archive:
            members = [name for name in archive.namelist() if name.endswith('.sc')]
            if len(members) != 1:
                raise ValueError('Expected exactly one .sc member per recording ZIP')
            with archive.open(members[0]) as raw:
                with io.TextIOWrapper(raw, encoding='utf-8') as stream:
                    yield stream
    else:
        with path.open(encoding='utf-8') as stream:
            yield stream


def audit(lines, limit=None):
    if limit is not None and limit <= 0:
        raise ValueError('limit must be positive')
    counts, calls, fields = Counter(), Counter(), {}
    first = last = previous = None
    for number, line in enumerate(lines):
        if limit is not None and number >= limit:
            break
        counts['lines'] += 1
        try:
            parts = line.strip().split(' ', 7)
            if len(parts) < 7 or not all(parts[:7]):
                raise ValueError('missing columns')
            timestamp, uid, pid, comm, tid, name, direction = parts[:7]
            timestamp = int(timestamp)
            if timestamp < 0 or direction not in ('>', '<'):
                raise ValueError('invalid timestamp or direction')
            int(uid), int(pid), int(tid)
            params = dict(token.split('=', 1) for token in parts[7].split() if '=' in token) if len(parts) == 8 else {}
        except ValueError:
            counts['malformed'] += 1
            continue
        counts['parsed'] += 1
        counts['entry' if direction == '>' else 'exit'] += 1
        counts['out_of_order'] += int(previous is not None and timestamp < previous)
        previous = timestamp
        first = timestamp if first is None else min(first, timestamp)
        last = timestamp if last is None else max(last, timestamp)
        calls[name + direction] += 1
        fields.setdefault(name + direction, set()).update(params)
    return dict(counts=dict(counts), syscall_directions=dict(calls),
                parameter_names={k: sorted(v) for k, v in sorted(fields.items())},
                first_timestamp_ns=first, last_timestamp_ns=last,
                duration_seconds=None if first is None else (last-first)/1e9,
                sampled=limit is not None,
                approved_for_native_training=False,
                unresolved=['Container vs whole-host coverage',
                            'Exec success/return semantics and process name at exec',
                            'Open variants, decoded paths and failure return codes',
                            'TCP-only connect filtering, completion semantics and destination decoding',
                            'Capture loss, start/end boundaries and attack interval labels'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('recording', type=Path)
    parser.add_argument('--limit', type=int)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with recording_lines(args.recording) as lines:
        result = audit(lines, args.limit)
    result['recording'] = str(args.recording.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
