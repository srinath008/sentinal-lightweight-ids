"""
feature_engineering/labeling.py
---------------------------------
Phase-label joining for the eBPF IDS dataset.

Takes a parsed event DataFrame (from parsing.py) and the corresponding
session's phase_log.csv, and adds two columns:
  - phase      : str  — one of 'baseline', 'attack_recon', 'attack_privesc',
                        'attack_fileaccess', or 'unlabeled' (for events that
                        fall outside all known phase windows)
  - session_id : str  — the session folder name (e.g. '20260914_120411')

Design notes:
  - Uses pd.IntervalIndex for O(log n) per-row lookup — not a Python loop —
    so it runs in acceptable time even on 8M-row opensnoop DataFrames.
  - Phase windows are treated as closed on both ends [start, end].
  - Rows outside all windows get phase='unlabeled'. A count is logged so
    gaps between phases can be quantified.
  - DataFrames from multiple sessions can be concatenated after labeling;
    session_id distinguishes them.
  - This module never modifies or overwrites the raw dataset files.
"""

from __future__ import annotations

import logging
from pathlib import Path

import numpy as np
import pandas as pd

log = logging.getLogger(__name__)

# Expected phase names in phase_log.csv (in order)
EXPECTED_PHASES = ('baseline', 'attack_recon', 'attack_privesc', 'attack_fileaccess')


def load_phase_log(phase_log_path: str | Path) -> pd.DataFrame:
    """
    Load a phase_log.csv file into a clean DataFrame.

    Expected format (with header row):
        phase,start_epoch,end_epoch
        baseline,1789367654.860455,1789371254.870929
        ...

    Returns a DataFrame with columns:
        phase (str), start_epoch (float64), end_epoch (float64)
    """
    df = pd.read_csv(phase_log_path)

    required = {'phase', 'start_epoch', 'end_epoch'}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(
            f"phase_log.csv missing expected columns: {missing}. "
            f"Found: {list(df.columns)}"
        )

    df['start_epoch'] = df['start_epoch'].astype(float)
    df['end_epoch']   = df['end_epoch'].astype(float)

    return df[['phase', 'start_epoch', 'end_epoch']].reset_index(drop=True)


def add_phase_labels(
    events_df: pd.DataFrame,
    phase_log_path: str | Path,
    session_id: str,
) -> pd.DataFrame:
    """
    Add 'phase' and 'session_id' columns to an events DataFrame.

    Parameters
    ----------
    events_df     : DataFrame with a 'timestamp' column (float, epoch seconds).
                    Produced by any of the loaders in parsing.py.
    phase_log_path: Path to the session's phase_log.csv.
    session_id    : String identifier for this session (e.g. '20260914_120411').
                    Written as-is into the 'session_id' column.

    Returns
    -------
    A copy of events_df with two new columns appended:
        session_id (str), phase (str)
    Rows with no matching phase window are assigned phase='unlabeled'.
    """
    phases = load_phase_log(phase_log_path)

    # Build a closed IntervalIndex over the phase windows for fast lookup.
    # pd.IntervalIndex.get_indexer() maps each timestamp to an interval index
    # (-1 = no match = unlabeled).
    intervals = pd.IntervalIndex.from_arrays(
        phases['start_epoch'],
        phases['end_epoch'],
        closed='both',
    )

    timestamps = events_df['timestamp'].to_numpy(dtype=float)

    # get_indexer returns the position in `intervals` for each value,
    # or -1 if no interval contains it.
    idx = intervals.get_indexer(timestamps)

    phase_labels = np.where(
        idx >= 0,
        phases['phase'].to_numpy()[idx],
        'unlabeled',
    )

    unlabeled_count = int((idx == -1).sum())
    if unlabeled_count > 0:
        log.info(
            "Session '%s': %d / %d events fell outside all phase windows "
            "(phase='unlabeled'). This is expected for brief inter-phase gaps.",
            session_id, unlabeled_count, len(events_df),
        )

    out = events_df.copy()
    out['session_id'] = session_id
    out['phase']      = phase_labels

    return out


def load_and_label_session(
    session_dir: str | Path,
    session_id: str,
    loader_fn,
    filename: str,
) -> pd.DataFrame:
    """
    Convenience wrapper: load one CSV file from a session directory and
    immediately apply phase labels.

    Parameters
    ----------
    session_dir : Path to a session folder (e.g. .../ids_dataset/20260914_120411/)
    session_id  : String identifier for this session
    loader_fn   : One of load_execsnoop / load_opensnoop / load_tcpconnect
                  from parsing.py
    filename    : The CSV filename within session_dir (e.g. 'execsnoop.csv')

    Returns
    -------
    Labeled DataFrame ready for feature engineering.
    """
    session_dir = Path(session_dir)
    csv_path      = session_dir / filename
    phase_log_path = session_dir / 'phase_log.csv'

    df = loader_fn(csv_path)
    df = add_phase_labels(df, phase_log_path, session_id)
    return df


def combine_sessions(labeled_dfs: list[pd.DataFrame]) -> pd.DataFrame:
    """
    Concatenate labeled DataFrames from multiple sessions into one combined
    DataFrame, preserving session_id to distinguish them.

    Sessions are kept independent — timestamps from different sessions
    are never mixed within a single time window during feature engineering
    (see features.py which groups by session_id before windowing).
    """
    if not labeled_dfs:
        raise ValueError("No DataFrames provided to combine_sessions()")

    combined = pd.concat(labeled_dfs, ignore_index=True)
    log.info(
        "Combined %d sessions → %d total rows",
        len(labeled_dfs), len(combined),
    )
    return combined
