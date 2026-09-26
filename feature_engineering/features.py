"""
feature_engineering/features.py
---------------------------------
Windowed feature extraction for the eBPF IDS dataset.

Takes labeled per-event DataFrames (from labeling.py) and produces a
fixed-time-window feature table ready for scikit-learn model input.

One row per (session_id, window_index) with the following feature columns:
    n_exec          - count of execsnoop events in window
    n_unique_pcomm  - count of distinct process names executed
    n_open          - count of opensnoop events in window
    n_unique_paths  - count of distinct file paths opened
    n_open_errors   - count of opensnoop events with err != 0
    n_tcp_connect   - count of tcpconnect events in window
    n_unique_daddr  - count of distinct destination addresses

Plus metadata columns (NOT model input features):
    session_id      - which session this window came from
    window_index    - integer window index within the session
    window_start    - epoch timestamp of the window's start
    phase           - majority phase label of events in this window
                      (for evaluation only — never used as model input)

Design decisions:
  - window_seconds is a tunable parameter (default 5.0s per §3.0).
  - Windows are computed per-session independently — timestamps from
    different sessions are never mixed (they were recorded on different days).
  - Windows with zero events for a given source still appear as 0-filled rows,
    not silently dropped.
  - opensnoop volume skew during attack_privesc (§2.6 item 2): we apply
    log1p transformation to n_open and n_unique_paths to prevent a small
    number of monolithic filesystem-scan windows from dominating the scale.
    The raw counts are preserved alongside as n_open_raw / n_unique_paths_raw
    so nothing is lost. (See NOTE below — this is documented as a judgment
    call for human review per §3.14.)

NOTE on log-transform decision (flagged per §3.14):
    The attack_privesc phase's opensnoop volume is dominated by getcap/find
    exhaustive filesystem scans (§2.6 item 2). Without transformation, a
    handful of windows with millions of opens would dwarf all other windows
    and likely cause both Isolation Forest and One-Class SVM to overfit to
    scale rather than structure. log1p is the standard choice for count data
    with extreme positive skew. The raw counts are retained so this decision
    can be revisited. Human sign-off on this choice is requested before WP-07.
"""

from __future__ import annotations

import logging
from pathlib import Path

import numpy as np
import pandas as pd

log = logging.getLogger(__name__)

# Default window size in seconds (tunable — see §3.0)
DEFAULT_WINDOW_SECONDS = 5.0

# Output path for saved feature tables
OUTPUT_DIR = Path(__file__).parent / 'output'


# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

def _assign_window_index(timestamps: pd.Series, window_seconds: float) -> pd.Series:
    """
    Bucket each timestamp into a fixed-duration window.

    Window index = floor((timestamp - session_min_timestamp) / window_seconds)

    Parameters
    ----------
    timestamps     : Series of float epoch timestamps (all from one session)
    window_seconds : Duration of each window in seconds

    Returns
    -------
    Series of integer window indices (same index as input)
    """
    t_min = timestamps.min()
    return ((timestamps - t_min) / window_seconds).apply(np.floor).astype(int)


def _majority_phase(phases: pd.Series) -> str:
    """Return the most common phase label in a group (used as window label)."""
    if phases.empty:
        return 'unlabeled'
    return phases.mode().iloc[0]


# ──────────────────────────────────────────────────────────────────────────────
# Per-source aggregation
# ──────────────────────────────────────────────────────────────────────────────

def _aggregate_execsnoop(
    exec_df: pd.DataFrame,
    window_seconds: float,
) -> pd.DataFrame:
    """
    Aggregate execsnoop events into per-window feature columns.

    Input must already have 'session_id', 'phase', 'timestamp', 'pcomm'.
    """
    if exec_df.empty:
        return pd.DataFrame(columns=[
            'session_id', 'window_index', 'phase',
            'n_exec', 'n_unique_pcomm',
        ])

    exec_df = exec_df.copy()
    exec_df['window_index'] = _assign_window_index(
        exec_df['timestamp'], window_seconds
    )

    agg = (
        exec_df
        .groupby(['session_id', 'window_index'])
        .agg(
            phase        = ('phase', _majority_phase),
            window_start = ('timestamp', 'min'),
            n_exec       = ('pcomm', 'count'),
            n_unique_pcomm = ('pcomm', 'nunique'),
        )
        .reset_index()
    )
    return agg


def _aggregate_opensnoop(
    open_df: pd.DataFrame,
    window_seconds: float,
) -> pd.DataFrame:
    """
    Aggregate opensnoop events into per-window feature columns.

    Input must already have 'session_id', 'phase', 'timestamp', 'path', 'err'.

    Applies log1p to n_open and n_unique_paths (see module docstring).
    """
    if open_df.empty:
        return pd.DataFrame(columns=[
            'session_id', 'window_index', 'phase', 'window_start',
            'n_open_raw', 'n_unique_paths_raw', 'n_open_errors',
            'n_open', 'n_unique_paths',
        ])

    open_df = open_df.copy()
    open_df['window_index'] = _assign_window_index(
        open_df['timestamp'], window_seconds
    )
    open_df['is_error'] = (open_df['err'].fillna(0) != 0).astype(int)

    agg = (
        open_df
        .groupby(['session_id', 'window_index'])
        .agg(
            phase              = ('phase', _majority_phase),
            window_start       = ('timestamp', 'min'),
            n_open_raw         = ('path', 'count'),
            n_unique_paths_raw = ('path', 'nunique'),
            n_open_errors      = ('is_error', 'sum'),
        )
        .reset_index()
    )

    # log1p-transform to reduce scale dominance from privesc filesystem crawls
    agg['n_open']         = np.log1p(agg['n_open_raw'])
    agg['n_unique_paths'] = np.log1p(agg['n_unique_paths_raw'])

    return agg


def _aggregate_tcpconnect(
    tcp_df: pd.DataFrame,
    window_seconds: float,
) -> pd.DataFrame:
    """
    Aggregate tcpconnect events into per-window feature columns.

    Input must already have 'session_id', 'phase', 'timestamp', 'daddr'.
    """
    if tcp_df.empty:
        return pd.DataFrame(columns=[
            'session_id', 'window_index',
            'n_tcp_connect', 'n_unique_daddr',
        ])

    tcp_df = tcp_df.copy()
    tcp_df['window_index'] = _assign_window_index(
        tcp_df['timestamp'], window_seconds
    )

    agg = (
        tcp_df
        .groupby(['session_id', 'window_index'])
        .agg(
            n_tcp_connect  = ('daddr', 'count'),
            n_unique_daddr = ('daddr', 'nunique'),
        )
        .reset_index()
    )
    return agg


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

def build_feature_table(
    exec_df: pd.DataFrame,
    open_df: pd.DataFrame,
    tcp_df: pd.DataFrame,
    window_seconds: float = DEFAULT_WINDOW_SECONDS,
) -> pd.DataFrame:
    """
    Build a windowed feature table from the three labeled event DataFrames
    for a single session.

    Parameters
    ----------
    exec_df        : Labeled execsnoop DataFrame (from labeling.py)
    open_df        : Labeled opensnoop DataFrame
    tcp_df         : Labeled tcpconnect DataFrame
    window_seconds : Window duration in seconds (default 5.0)

    Returns
    -------
    DataFrame with one row per (session_id, window_index), columns:
        session_id, window_index, window_start, phase,
        n_exec, n_unique_pcomm,
        n_open_raw, n_unique_paths_raw, n_open_errors, n_open, n_unique_paths,
        n_tcp_connect, n_unique_daddr

    All count/feature columns are 0-filled for windows where that source
    had no events — no rows are dropped.
    """
    exec_agg = _aggregate_execsnoop(exec_df, window_seconds)
    open_agg = _aggregate_opensnoop(open_df, window_seconds)
    tcp_agg  = _aggregate_tcpconnect(tcp_df, window_seconds)

    # Derive the full window grid from whichever source has the widest span.
    # Use opensnoop as the anchor (highest event density → most complete grid).
    # Fall back to exec if opensnoop is empty.
    anchor = open_agg if not open_agg.empty else exec_agg
    if anchor.empty:
        log.warning("All three event sources are empty — returning empty feature table.")
        return pd.DataFrame()

    session_ids = anchor['session_id'].unique()
    all_windows = []

    for sid in session_ids:
        # Collect all window indices that appear in any of the three sources
        exec_w = set(exec_agg.loc[exec_agg['session_id'] == sid, 'window_index'].tolist())
        open_w = set(open_agg.loc[open_agg['session_id'] == sid, 'window_index'].tolist())
        tcp_w  = set(tcp_agg.loc[tcp_agg['session_id']  == sid, 'window_index'].tolist())
        all_w  = sorted(exec_w | open_w | tcp_w)

        if not all_w:
            continue

        grid = pd.DataFrame({'session_id': sid, 'window_index': all_w})

        # Merge exec features
        e_cols = ['session_id', 'window_index', 'phase', 'window_start',
                  'n_exec', 'n_unique_pcomm']
        grid = grid.merge(
            exec_agg[exec_agg['session_id'] == sid][e_cols],
            on=['session_id', 'window_index'], how='left',
        )

        # Merge open features
        o_cols = ['session_id', 'window_index',
                  'n_open_raw', 'n_unique_paths_raw', 'n_open_errors',
                  'n_open', 'n_unique_paths']
        grid = grid.merge(
            open_agg[open_agg['session_id'] == sid][o_cols],
            on=['session_id', 'window_index'], how='left',
        )

        # Merge tcp features
        t_cols = ['session_id', 'window_index', 'n_tcp_connect', 'n_unique_daddr']
        grid = grid.merge(
            tcp_agg[tcp_agg['session_id'] == sid][t_cols],
            on=['session_id', 'window_index'], how='left',
        )

        all_windows.append(grid)

    features = pd.concat(all_windows, ignore_index=True)

    # Fill missing phase from open_agg (which has highest coverage)
    open_phase = open_agg[['session_id', 'window_index', 'phase']].rename(
        columns={'phase': 'phase_open'}
    )
    features = features.merge(open_phase, on=['session_id', 'window_index'], how='left')
    features['phase'] = features['phase'].fillna(features['phase_open'])
    features = features.drop(columns=['phase_open'])

    # Fill missing window_start from opensnoop
    open_wstart = open_agg[['session_id', 'window_index', 'window_start']].rename(
        columns={'window_start': 'ws_open'}
    )
    features = features.merge(open_wstart, on=['session_id', 'window_index'], how='left')
    features['window_start'] = features['window_start'].fillna(features['ws_open'])
    features = features.drop(columns=['ws_open'])

    # Zero-fill all count columns (NaN means 0 events from that source)
    count_cols = [
        'n_exec', 'n_unique_pcomm',
        'n_open_raw', 'n_unique_paths_raw', 'n_open_errors',
        'n_open', 'n_unique_paths',
        'n_tcp_connect', 'n_unique_daddr',
    ]
    features[count_cols] = features[count_cols].fillna(0)

    # Fill remaining unlabeled phases
    features['phase'] = features['phase'].fillna('unlabeled')

    # Final column order
    col_order = [
        'session_id', 'window_index', 'window_start', 'phase',
        'n_exec', 'n_unique_pcomm',
        'n_open_raw', 'n_unique_paths_raw', 'n_open_errors',
        'n_open', 'n_unique_paths',
        'n_tcp_connect', 'n_unique_daddr',
    ]
    features = features[col_order]

    # Ensure integer types for raw counts
    int_cols = ['n_exec', 'n_unique_pcomm', 'n_open_raw', 'n_unique_paths_raw',
                'n_open_errors', 'n_tcp_connect', 'n_unique_daddr']
    for col in int_cols:
        features[col] = features[col].astype(int)

    log.info(
        "Session '%s': %d windows of %.1fs (%.0f–%.0f events/window for opensnoop)",
        features['session_id'].iloc[0] if len(features) else '?',
        len(features),
        window_seconds,
        features['n_open_raw'].min(),
        features['n_open_raw'].max(),
    )

    return features


def save_features(features: pd.DataFrame, window_seconds: float) -> Path:
    """
    Save the feature table to a .parquet file in feature_engineering/output/.

    Filename pattern: features_window<N>s.parquet
    where N is the window size in seconds (integer if whole number, else float).

    Returns the path to the saved file.
    """
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    n = int(window_seconds) if window_seconds == int(window_seconds) else window_seconds
    filename = f'features_window{n}s.parquet'
    out_path = OUTPUT_DIR / filename

    features.to_parquet(out_path, index=False)
    log.info("Feature table saved → %s (%d rows)", out_path, len(features))
    return out_path


def load_features(window_seconds: float = DEFAULT_WINDOW_SECONDS) -> pd.DataFrame:
    """
    Load a previously saved feature table from parquet.

    Parameters
    ----------
    window_seconds : Must match the window size used when save_features() was called.
    """
    n = int(window_seconds) if window_seconds == int(window_seconds) else window_seconds
    path = OUTPUT_DIR / f'features_window{n}s.parquet'
    if not path.exists():
        raise FileNotFoundError(
            f"Feature table not found: {path}\n"
            f"Run build_feature_table() and save_features() first."
        )
    return pd.read_parquet(path)
