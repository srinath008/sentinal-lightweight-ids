"""
feature_engineering/parsing.py
--------------------------------
Raw log loaders for the three eBPF capture file types produced by
collect_dataset.sh (execsnoop, opensnoop, tcpconnect).

Each file has the shape:
    <epoch_float>,<tool native output line (space-delimited)>

The very first line of each file is the tool's own column-header text
(e.g. "PCOMM  PID  PPID  RET ARGS"), prefixed with a timestamp.
This header line must be detected and skipped — it is NOT data.

All loaders return a clean pandas.DataFrame with typed, named columns.

Column schemas (after the leading timestamp):
  execsnoop : PCOMM  PID  PPID  RET  ARGS
  opensnoop : PID  COMM  FD  ERR  PATH
  tcpconnect: PID  COMM  IP  SADDR  DADDR  DPORT

The final column in execsnoop (ARGS) and opensnoop (PATH) may contain
embedded spaces — it is treated as "everything remaining" and is NOT
split further.
"""

from __future__ import annotations

import re
from pathlib import Path

import pandas as pd


# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

# Regex that matches the injected timestamp at the start of every line.
# Captures a float in group 1, the rest of the line in group 2.
_LINE_RE = re.compile(r'^(\d+\.\d+),(.+)$')


def _is_header_line(fields: list[str], pid_col_index: int) -> bool:
    """
    Return True if the parsed fields look like the tool's own header row
    rather than a real data row.

    Strategy: the column that should hold a numeric PID is non-numeric
    in the header row (it will be the literal column name, e.g. "PID").
    """
    if pid_col_index >= len(fields):
        return False
    try:
        int(fields[pid_col_index])
        return False          # successfully parsed as int → real data row
    except (ValueError, TypeError):
        return True           # not an int → header row


def _parse_file(
    path: str | Path,
    *,
    min_fields: int,
    pid_col_index: int,
    trailing_col_index: int,
) -> tuple[list[float], list[list[str]]]:
    """
    Generic file reader.

    Returns (timestamps, field_lists) where each field_list has exactly
    min_fields elements (the last one may contain embedded spaces).

    Skips:
      - Lines that don't match the timestamp prefix pattern.
      - The tool's own header line (detected via pid_col_index).
    """
    timestamps: list[float] = []
    rows: list[list[str]] = []

    with open(path, 'r', encoding='utf-8', errors='replace') as fh:
        for raw in fh:
            raw = raw.rstrip('\n\r')
            m = _LINE_RE.match(raw)
            if not m:
                continue

            ts = float(m.group(1))
            rest = m.group(2).strip()

            # Split into at most min_fields parts so the trailing column
            # (ARGS / PATH) absorbs embedded spaces.
            parts = rest.split(None, min_fields - 1)

            if len(parts) < min_fields:
                # Too few fields — malformed line, skip silently.
                continue

            if _is_header_line(parts, pid_col_index):
                continue

            timestamps.append(ts)
            rows.append(parts)

    return timestamps, rows


# ──────────────────────────────────────────────────────────────────────────────
# Public loaders
# ──────────────────────────────────────────────────────────────────────────────

def load_execsnoop(path: str | Path) -> pd.DataFrame:
    """
    Load an execsnoop.csv into a DataFrame.

    Columns: timestamp (float64), pcomm (str), pid (int64),
             ppid (int64), ret (int64), args (str)

    The header line (PCOMM PID PPID RET ARGS) is skipped automatically.
    ARGS is the trailing column and may contain spaces.
    """
    # Schema: PCOMM PID PPID RET ARGS  → 5 fields, PID at index 1
    timestamps, rows = _parse_file(
        path,
        min_fields=5,
        pid_col_index=1,
        trailing_col_index=4,
    )

    df = pd.DataFrame(rows, columns=['pcomm', 'pid', 'ppid', 'ret', 'args'])
    df.insert(0, 'timestamp', timestamps)

    df['pid']  = pd.to_numeric(df['pid'],  errors='coerce').astype('Int64')
    df['ppid'] = pd.to_numeric(df['ppid'], errors='coerce').astype('Int64')
    df['ret']  = pd.to_numeric(df['ret'],  errors='coerce').astype('Int64')

    return df


def _is_int(s: str) -> bool:
    """Return True if s represents a (possibly negative) integer."""
    try:
        int(s)
        return True
    except (ValueError, TypeError):
        return False


def load_opensnoop(path: str | Path) -> pd.DataFrame:
    """
    Load an opensnoop.csv into a DataFrame.

    Columns: timestamp (float64), pid (int64), comm (str),
             fd (int64), err (int64), path (str)

    The header line (PID COMM FD ERR PATH) is skipped automatically.

    Special handling: COMM may contain spaces (e.g. "StreamT~ns #132",
    "BgIOThr~Pool #8"). Since PID is always the first numeric token and
    FD/ERR are the last two consecutive integer tokens before the PATH
    string, we anchor from both ends:
      - PID  = first token (must be numeric)
      - FD   = last consecutive integer-pair, first element
      - ERR  = last consecutive integer-pair, second element
      - COMM = everything between PID and FD
      - PATH = everything after ERR
    """
    _HEADER_PID = re.compile(r'^PID\b', re.IGNORECASE)

    timestamps: list[float] = []
    pids: list[str] = []
    comms: list[str] = []
    fds: list[str] = []
    errs: list[str] = []
    paths: list[str] = []

    with open(path, 'r', encoding='utf-8', errors='replace') as fh:
        for raw in fh:
            raw = raw.rstrip('\n\r')
            m = _LINE_RE.match(raw)
            if not m:
                continue

            ts = float(m.group(1))
            rest = m.group(2).strip()
            tokens = rest.split()

            if not tokens:
                continue

            # Skip header line — first token is "PID" (non-numeric)
            if _HEADER_PID.match(tokens[0]):
                continue

            # PID must be the first token and must be numeric
            if not _is_int(tokens[0]):
                continue

            # Need at least PID COMM FD ERR PATH = 4 meaningful pieces,
            # so minimum 4 tokens (COMM and PATH could each be one word)
            if len(tokens) < 4:
                continue

            # Find FD index: the rightmost position i such that
            # tokens[i] is a plausible FD (non-negative integer) and
            # tokens[i+1] is a plausible ERR (small integer, -4096..4096).
            # The ERR range check rejects large numeric strings that appear
            # in PATH (e.g. directory names like '20260914_120411' when
            # the find/getcap commands scan the ids_dataset folder).
            fd_idx = None
            for i in range(1, len(tokens) - 1):
                try:
                    fd_candidate  = int(tokens[i])
                    err_candidate = int(tokens[i + 1])
                except (ValueError, TypeError):
                    continue
                if fd_candidate >= 0 and -4096 <= err_candidate <= 4096:
                    fd_idx = i  # keep updating → last valid pair wins

            if fd_idx is None or fd_idx + 1 >= len(tokens):
                continue

            pid_val  = tokens[0]
            fd_val   = tokens[fd_idx]
            err_val  = tokens[fd_idx + 1]
            comm_val = ' '.join(tokens[1:fd_idx])
            path_val = ' '.join(tokens[fd_idx + 2:]) if fd_idx + 2 < len(tokens) else ''

            timestamps.append(ts)
            pids.append(pid_val)
            comms.append(comm_val)
            fds.append(fd_val)
            errs.append(err_val)
            paths.append(path_val)

    df = pd.DataFrame({
        'timestamp': timestamps,
        'pid':  pids,
        'comm': comms,
        'fd':   fds,
        'err':  errs,
        'path': paths,
    })

    df['pid'] = pd.to_numeric(df['pid'], errors='coerce').astype('Int64')
    df['fd']  = pd.to_numeric(df['fd'],  errors='coerce').astype('Int64')
    df['err'] = pd.to_numeric(df['err'], errors='coerce').astype('Int64')

    return df


def load_tcpconnect(path: str | Path) -> pd.DataFrame:
    """
    Load a tcpconnect.csv into a DataFrame.

    Columns: timestamp (float64), pid (int64), comm (str),
             ip (int64), saddr (str), daddr (str), dport (int64)

    The header line (PID COMM IP SADDR DADDR DPORT) is skipped
    automatically.

    Special handling: COMM may contain spaces (e.g. "Socket Thread").
    The last 4 tokens are always IP(4|6), SADDR, DADDR, DPORT — all
    single well-formed tokens. We anchor from the right:
      - DPORT = last token
      - DADDR = second-to-last
      - SADDR = third-to-last
      - IP    = fourth-to-last (must be '4' or '6')
      - PID   = first token
      - COMM  = everything between PID and IP
    """
    _HEADER_PID = re.compile(r'^PID\b', re.IGNORECASE)

    timestamps: list[float] = []
    pids: list[str] = []
    comms: list[str] = []
    ips: list[str] = []
    saddrs: list[str] = []
    daddrs: list[str] = []
    dports: list[str] = []

    with open(path, 'r', encoding='utf-8', errors='replace') as fh:
        for raw in fh:
            raw = raw.rstrip('\n\r')
            m = _LINE_RE.match(raw)
            if not m:
                continue

            ts = float(m.group(1))
            rest = m.group(2).strip()
            tokens = rest.split()

            if not tokens:
                continue

            # Skip header line — first token is "PID" (non-numeric)
            if _HEADER_PID.match(tokens[0]):
                continue

            # Need at least PID COMM IP SADDR DADDR DPORT = 6 tokens
            if len(tokens) < 6:
                continue

            # PID must be the first token and numeric
            if not _is_int(tokens[0]):
                continue

            # Anchor from the right: last 4 tokens = IP SADDR DADDR DPORT
            dport_val = tokens[-1]
            daddr_val = tokens[-2]
            saddr_val = tokens[-3]
            ip_val    = tokens[-4]

            # Sanity: ip must be '4' or '6'
            if ip_val not in ('4', '6'):
                continue

            pid_val  = tokens[0]
            comm_val = ' '.join(tokens[1:-4])

            timestamps.append(ts)
            pids.append(pid_val)
            comms.append(comm_val)
            ips.append(ip_val)
            saddrs.append(saddr_val)
            daddrs.append(daddr_val)
            dports.append(dport_val)

    df = pd.DataFrame({
        'timestamp': timestamps,
        'pid':   pids,
        'comm':  comms,
        'ip':    ips,
        'saddr': saddrs,
        'daddr': daddrs,
        'dport': dports,
    })

    df['pid']   = pd.to_numeric(df['pid'],   errors='coerce').astype('Int64')
    df['ip']    = pd.to_numeric(df['ip'],    errors='coerce').astype('Int64')
    df['dport'] = pd.to_numeric(df['dport'], errors='coerce').astype('Int64')

    return df
