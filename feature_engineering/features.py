"""Shared-origin window features; use replay.py for large raw datasets."""
import logging
from pathlib import Path
import numpy as np
import pandas as pd

log = logging.getLogger(__name__)
DEFAULT_WINDOW_SECONDS = 5.0
OUTPUT_DIR = Path(__file__).parent / "output"


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
    if not np.isfinite(window_seconds) or window_seconds <= 0:
        raise ValueError('window_seconds must be finite and positive')
    t_min = timestamps.min()
    return ((timestamps - t_min) / window_seconds).apply(np.floor).astype(int)


def build_feature_table(exec_df, open_df, tcp_df, window_seconds=DEFAULT_WINDOW_SECONDS):
    """Aggregate all sources on one origin per session, including empty windows."""
    from feature_engineering.events import Window, window_index
    if not np.isfinite(window_seconds) or window_seconds <= 0:
        raise ValueError('window_seconds must be finite and positive')
    frames = [('execsnoop', exec_df), ('opensnoop', open_df), ('tcpconnect', tcp_df)]
    sessions = sorted({s for _, df in frames if not df.empty for s in df.session_id.unique()})
    rows = []
    for sid in sessions:
        subsets = [(source, df[df.session_id == sid]) for source, df in frames]
        origin = min(df.timestamp.min() for _, df in subsets if not df.empty)
        end = max(df.timestamp.max() for _, df in subsets if not df.empty)
        windows = {}
        for source, df in subsets:
            for record in df.itertuples(index=False):
                event = record._asdict()
                idx = window_index(event['timestamp'], origin, window_seconds)
                windows.setdefault(idx, Window()).add(source, event, event.get('phase', 'unlabeled'))
        for idx in range(window_index(end, origin, window_seconds) + 1):
            rows.append(windows.get(idx, Window()).row(sid, idx, origin, window_seconds))
    return pd.DataFrame(rows)


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
