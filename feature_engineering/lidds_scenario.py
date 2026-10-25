"""Audit official nested LID-DS scenario ZIPs and build a diagnostic feature view.

The view is NOT certified as native whole-host telemetry. In particular, the
window origin uses all exported syscalls and capture coverage is container based.
No archive members or payloads are extracted or executed.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import io
import json
from pathlib import Path
import re
import zipfile
import pandas as pd
from feature_engineering.events import Window


def parameters(text):
    matches = list(re.finditer(r'(?:^|\s)([a-zA-Z_][a-zA-Z_0-9]*)=', text))
    return {m.group(1): text[m.end():matches[i+1].start() if i+1 < len(matches) else len(text)].strip()
            for i, m in enumerate(matches)}


def number(text):
    match = re.match(r'^(-?\d+)', text or '')
    if not match:
        raise ValueError('Missing numeric return or argument')
    return int(match.group(1))


def inspect_recording(data, session, split):
    calls, stats, processes = Counter(), Counter(), Counter()
    pending_socket, sockets, pending_connect = {}, {}, {}
    windows = defaultdict(Window)
    first = last = previous = None
    with zipfile.ZipFile(io.BytesIO(data)) as recording:
        names = recording.namelist()
        metadata_name, = [n for n in names if n.endswith('.json')]
        syscall_name, = [n for n in names if n.endswith('.sc')]
        metadata = json.loads(recording.read(metadata_name))
        attack_times = [float(item['absolute']) for item in metadata['time']['exploit']]
        onset = min(attack_times) if attack_times else None
        if bool(metadata['exploit']) != (onset is not None):
            raise ValueError('Exploit metadata and attack timestamps disagree')
        with recording.open(syscall_name) as stream:
            for raw in stream:
                stats['lines'] += 1
                try:
                    parts = raw.decode('utf-8').rstrip().split(' ', 7)
                    timestamp, uid, pid, comm, tid, call, direction = parts[:7]
                    timestamp, pid, tid = int(timestamp), int(pid), int(tid)
                    if timestamp < 0 or direction not in ('>', '<'):
                        raise ValueError('invalid event')
                    needs_args = call in ('socket', 'connect', 'close', 'execve', 'execveat',
                                          'open', 'openat', 'openat2')
                    args = parameters(parts[7]) if needs_args and len(parts) > 7 else {}
                except (ValueError, UnicodeError):
                    stats['malformed'] += 1
                    continue
                stats['out_of_order'] += int(previous is not None and timestamp < previous)
                previous = timestamp
                first = timestamp if first is None else first
                last = timestamp if last is None else max(last, timestamp)
                calls[call + direction] += 1
                processes[comm] += 1
                index = (timestamp - first) // 5_000_000_000
                if index < 0:
                    stats['before_origin'] += 1
                    continue
                window = windows[index]
                # Additional diagnostic signal; never silently expand native schema.
                if direction == '<' and call in ('accept', 'accept4', 'clone', 'read', 'write'):
                    stats[call + '_exits'] += 1
                try:
                    if call == 'socket':
                        if direction == '>':
                            pending_socket[tid] = (number(args.get('domain')), number(args.get('type')) & 15,
                                                   number(args.get('proto')))
                        else:
                            fd = number(args.get('fd'))
                            info = pending_socket.pop(tid, None)
                            if fd >= 0 and info is not None:
                                sockets[pid, fd] = info
                    elif call == 'connect':
                        if direction == '>':
                            fd = number(args.get('fd'))
                            pending_connect[tid] = sockets.get((pid, fd))
                        else:
                            info = pending_connect.pop(tid, None)
                            if info is None:
                                stats['connect_unknown_protocol'] += 1
                                continue
                            family, socktype, protocol = info
                            if family not in (2, 10):
                                stats['connect_non_inet'] += 1
                                continue
                            if socktype == 2:
                                stats['udp_connect_exits'] += 1
                                continue
                            if socktype != 1 or protocol not in (0, 6):
                                stats['connect_unknown_protocol'] += 1
                                continue
                            stats['tcp_connect_exits'] += 1
                            if number(args.get('res')) == 0:
                                destination = args['tuple'].split('->', 1)[1].rsplit(':', 1)[0]
                                window.add('tcpconnect', {'daddr': destination})
                    elif call == 'close' and direction == '>':
                        # Conservative invalidate at close entry; no reused-FD inference.
                        sockets.pop((pid, number(args.get('fd'))), None)
                    elif call in ('execve', 'execveat') and direction == '<':
                        if number(args.get('res')) == 0:
                            window.add('execsnoop', {'pcomm': comm})
                    elif call in ('open', 'openat', 'openat2') and direction == '<':
                        fd = number(args.get('fd'))
                        if not args.get('name'):
                            raise ValueError('missing pathname')
                        window.add('opensnoop', {'path': args['name'], 'err': int(fd < 0)})
                except (ValueError, KeyError, IndexError):
                    stats['unresolved_feature_events'] += 1
    if first is None:
        raise ValueError('No parsed events in recording')
    rows = []
    # Only buckets fully contained in observed span. A final partial bucket is omitted.
    for index in range((last-first) // 5_000_000_000):
        row = windows[index].row(session, index, first/1e9, 5.)
        start, end = row['window_start'], row['window_start'] + 5.
        if onset is None:
            phase = 'baseline'
        elif end <= onset:
            phase = 'baseline'
        elif start >= onset:
            phase = 'attack_exposure'
        else:
            stats['omitted_transition_windows'] += 1
            continue
        row.update(phase=phase, dataset='LID-DS-2021', partition=split,
                   certified_native_compatible=False)
        rows.append(row)
    return rows, dict(session_id=session, partition=split, exploit=metadata['exploit'],
                      image=metadata['image'], recording_seconds=metadata['recording_time'],
                      observed_seconds=(last-first)/1e9, attack_onset=onset,
                      process_names=dict(processes), stats=dict(stats), calls=dict(calls))


def run(archive_path, output, summary_path=None):
    output.mkdir(parents=True, exist_ok=True)
    with archive_path.open('rb') as raw:
        digest = hashlib.file_digest(raw, 'sha256').hexdigest()
    rows, records = [], []
    with zipfile.ZipFile(archive_path) as archive:
        members = sorted(n for n in archive.namelist() if n.endswith('.zip') and not n.startswith('__MACOSX/'))
        for i, member in enumerate(members, 1):
            split = 'training' if '/training/' in member else 'validation' if '/validation/' in member else 'test'
            values, audit = inspect_recording(archive.read(member), member, split)
            audit['archive_member'] = member
            rows.extend(values)
            records.append(audit)
            if i % 25 == 0:
                print(f'Audited {i}/{len(members)} recordings', flush=True)
    frame = pd.DataFrame(rows)
    frame.to_parquet(output / 'diagnostic_features.parquet', index=False)
    totals, calls, processes = Counter(), Counter(), Counter()
    for record in records:
        totals.update(record['stats']); calls.update(record['calls']); processes.update(record['process_names'])
    report = dict(archive=str(archive_path.resolve()), archive_bytes=archive_path.stat().st_size,
                  sha256=digest, recordings=len(records), windows=len(frame),
                  partitions=dict(Counter(r['partition'] for r in records)),
                  exploit_recordings=sum(r['exploit'] for r in records),
                  stats=dict(totals), calls=dict(calls), process_names=dict(processes),
                  approved_for_native_training=False,
                  limitations=['Victim container scope differs from whole-host scope',
                               'Origin uses first exported syscall, not first native collector event',
                               'Attack exposure after recorded onset is not proof every window is malicious',
                               'No capture-loss completeness certificate',
                               'One old MySQL authentication scenario is not desktop activity diversity'],
                  records=records)
    (output / 'audit.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    if summary_path is not None:
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(json.dumps({k:v for k,v in report.items() if k != 'records'}, indent=2), encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k != 'records'}, indent=2), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, default=Path('external_data/lidds/CVE-2012-2122.zip'))
    parser.add_argument('--output', type=Path, default=Path('external_data/lidds/audit'))
    parser.add_argument('--summary', type=Path, default=Path('docs/LIDDS_AUDIT_SUMMARY.json'))
    args = parser.parse_args()
    run(args.archive, args.output, args.summary)


if __name__ == '__main__':
    main()
