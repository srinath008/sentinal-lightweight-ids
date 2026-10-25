"""Shared incremental parsing and aggregation for replay and live collection."""
from collections import Counter
from math import floor, isfinite, log1p
import re

FEATURES = ['n_exec', 'n_unique_pcomm', 'n_open', 'n_unique_paths',
            'n_open_errors', 'n_tcp_connect', 'n_unique_daddr']
SCHEMA_VERSION = 2
SOURCES = ('execsnoop', 'opensnoop', 'tcpconnect')


def parse_event(source, raw):
    """Parse native CO-RE text; headers return None, malformed events raise."""
    raw = raw.strip()
    if not raw:
        return None
    if raw.split()[0] in ('PID', 'PCOMM'):
        return None
    if source == 'execsnoop':
        match = re.match(r'^(.*?)\s+(\d+)\s+(\d+)\s+(-?\d+)\s+(.*)$', raw)
        if not match:
            raise ValueError('invalid execsnoop row')
        comm, pid, ppid, ret, args = match.groups()
        return dict(pcomm=comm, pid=int(pid), ppid=int(ppid), ret=int(ret), args=args)
    if source == 'opensnoop':
        # Fixed-width spacing identifies the FD/ERR pair before PATH; first
        # plausible pair avoids interpreting numbers in the trailing path.
        match = re.match(r'^(\d+)\s+(.*?)\s+(-?\d+)\s+(-?\d+)\s+(.*)$', raw)
        if not match:
            raise ValueError('invalid opensnoop row')
        pid, comm, fd, err, path = match.groups()
        if int(fd) < -1 or not -4096 <= int(err) <= 4096 or not comm or not path:
            raise ValueError('invalid opensnoop fields')
        return dict(pid=int(pid), comm=comm, fd=int(fd), err=int(err), path=path)
    if source == 'tcpconnect':
        tokens = raw.split()
        if len(tokens) < 6 or tokens[-4] not in ('4', '6'):
            raise ValueError('invalid tcpconnect row')
        port = int(tokens[-1])
        if not 0 <= port <= 65535:
            raise ValueError('invalid TCP port')
        return dict(pid=int(tokens[0]), comm=' '.join(tokens[1:-4]),
                    ip=int(tokens[-4]), saddr=tokens[-3], daddr=tokens[-2], dport=port)
    raise ValueError('unknown source: ' + source)


class Window:
    """Store counters and distinct values, never complete event histories."""
    def __init__(self):
        self.exec_count = self.open_count = self.errors = self.tcp_count = 0
        self.processes, self.paths, self.destinations = set(), set(), set()
        self.phases = Counter()

    def add(self, source, event, phase='unlabeled'):
        self.phases[phase] += 1
        if source == 'execsnoop':
            self.exec_count += 1
            self.processes.add(event['pcomm'])
        elif source == 'opensnoop':
            self.open_count += 1
            self.paths.add(event['path'])
            self.errors += int(event['err'] != 0)
        elif source == 'tcpconnect':
            self.tcp_count += 1
            self.destinations.add(event['daddr'])
        else:
            raise ValueError('unknown source')

    def row(self, session, index, origin, seconds):
        phase = sorted(self.phases, key=lambda p: (-self.phases[p], p))[0] if self.phases else 'unlabeled'
        return dict(session_id=session, window_index=index,
                    window_start=origin + index * seconds, phase=phase,
                    n_exec=self.exec_count, n_unique_pcomm=len(self.processes),
                    n_open_raw=self.open_count, n_unique_paths_raw=len(self.paths),
                    n_open_errors=self.errors, n_open=log1p(self.open_count),
                    n_unique_paths=log1p(len(self.paths)),
                    n_tcp_connect=self.tcp_count, n_unique_daddr=len(self.destinations))


def window_index(timestamp, origin, seconds):
    if not all(isfinite(x) for x in (timestamp, origin, seconds)) or seconds <= 0:
        raise ValueError('invalid window timing')
    return floor((timestamp - origin) / seconds)
