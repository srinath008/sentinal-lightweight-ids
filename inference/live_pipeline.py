"""
inference/live_pipeline.py
----------------------------
WP-11: Live inference pipeline for the eBPF IDS.

LEGACY REPLAY ONLY: use python -m inference.replay with a validated bundle
for corrected replay, or python -m inference.streaming on Linux for monitoring.
This legacy path uses historical models that are incompatible with corrected
shared-origin feature windows and must not be used for new inference.

Simulates real-time anomaly detection by processing a directory of eBPF
log files, extracting features in sliding windows, and scoring them with
the trained Isolation Forest + One-Class SVM models.

In a real deployment, this script would be triggered every window_seconds
by a cron/systemd timer, reading from live BCC tool output files.
For evaluation/demo purposes it replays a session directory.

Usage:
    python inference/live_pipeline.py --session-dir <path> [--window 5.0]

Output:
    Prints one alert line per anomalous window to stdout (JSON format),
    and saves a full scored log to inference/output/live_scores.parquet.

Alert format (JSON, one per line):
    {
      "window_start": <epoch float>,
      "window_index": <int>,
      "phase_true":   <str>,     # ground-truth label (demo only)
      "if_anomaly":   <bool>,
      "if_score":     <float>,
      "ocsvm_anomaly":<bool>,
      "ocsvm_score":  <float>,
      "verdict":      "ANOMALY" | "NORMAL"
    }
"""

from __future__ import annotations
import sys
import json
import logging
import argparse
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s',
                    datefmt='%H:%M:%S')
log = logging.getLogger(__name__)

# ── paths ────────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from feature_engineering.parsing  import load_execsnoop, load_opensnoop, load_tcpconnect
from feature_engineering.labeling import add_phase_labels
from feature_engineering.features import build_feature_table, DEFAULT_WINDOW_SECONDS

MODELS_DIR   = PROJECT_ROOT / 'models' / 'output'
OUTPUT_DIR   = PROJECT_ROOT / 'inference' / 'output'
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

IF_MODEL_PATH    = MODELS_DIR / 'isolation_forest.joblib'
OCSVM_MODEL_PATH = MODELS_DIR / 'ocsvm.joblib'
SCALER_PATH      = MODELS_DIR / 'ocsvm_scaler.joblib'

MODEL_FEATURES = [
    'n_exec', 'n_unique_pcomm',
    'n_open', 'n_unique_paths',
    'n_open_errors',
    'n_tcp_connect', 'n_unique_daddr',
]


# ──────────────────────────────────────────────────────────────────────────────
# Load models (once at startup)
# ──────────────────────────────────────────────────────────────────────────────

def load_models() -> tuple:
    """Load IF model, OC-SVM model, and scaler from disk."""
    for path in (IF_MODEL_PATH, OCSVM_MODEL_PATH, SCALER_PATH):
        if not path.exists():
            raise FileNotFoundError(
                f'Model file not found: {path}\n'
                f'Run models/train_isolation_forest.py and models/train_ocsvm.py first.'
            )
    clf_if    = joblib.load(IF_MODEL_PATH)
    clf_ocsvm = joblib.load(OCSVM_MODEL_PATH)
    scaler    = joblib.load(SCALER_PATH)
    log.info('Loaded: IsolationForest, OneClassSVM, StandardScaler')
    return clf_if, clf_ocsvm, scaler


# ──────────────────────────────────────────────────────────────────────────────
# Feature extraction from a session directory
# ──────────────────────────────────────────────────────────────────────────────

def extract_features(
    session_dir: Path,
    session_id: str,
    window_seconds: float = DEFAULT_WINDOW_SECONDS,
) -> pd.DataFrame:
    """
    Parse the three eBPF log files from a session directory,
    add phase labels (if phase_log.csv is present, else 'unlabeled'),
    and build the feature table.
    """
    log.info('Parsing session: %s', session_dir)

    exec_csv  = session_dir / 'execsnoop.csv'
    open_csv  = session_dir / 'opensnoop.csv'
    tcp_csv   = session_dir / 'tcpconnect.csv'
    phase_csv = session_dir / 'phase_log.csv'

    exec_df = load_execsnoop(exec_csv)
    open_df = load_opensnoop(open_csv)
    tcp_df  = load_tcpconnect(tcp_csv)

    log.info('  exec=%d  open=%d  tcp=%d', len(exec_df), len(open_df), len(tcp_df))

    # Label phases if available (for demo/evaluation); else mark all 'unlabeled'
    if phase_csv.exists():
        exec_df = add_phase_labels(exec_df, phase_csv, session_id)
        open_df = add_phase_labels(open_df, phase_csv, session_id)
        tcp_df  = add_phase_labels(tcp_df,  phase_csv, session_id)
    else:
        for df in (exec_df, open_df, tcp_df):
            df['phase']      = 'unlabeled'
            df['session_id'] = session_id

    ft = build_feature_table(exec_df, open_df, tcp_df, window_seconds=window_seconds)
    log.info('  Feature table: %d windows', len(ft))
    return ft


# ──────────────────────────────────────────────────────────────────────────────
# Score windows
# ──────────────────────────────────────────────────────────────────────────────

def score_windows(
    ft: pd.DataFrame,
    clf_if,
    clf_ocsvm,
    scaler,
) -> pd.DataFrame:
    """
    Apply both models to the feature table and return a scored DataFrame.

    Verdict logic:
        IF predicts anomaly → ANOMALY  (primary, zero missed attacks)
        else               → NORMAL
    OC-SVM score is recorded as a secondary severity signal.
    """
    X_raw = ft[MODEL_FEATURES].to_numpy(dtype=float)
    X_scaled = scaler.transform(X_raw)

    if_scores   = clf_if.score_samples(X_raw)
    if_preds    = clf_if.predict(X_raw)          # +1 normal, -1 anomaly

    ocsvm_scores = clf_ocsvm.decision_function(X_scaled)
    ocsvm_preds  = clf_ocsvm.predict(X_scaled)

    results = ft[['session_id', 'window_index', 'window_start', 'phase']].copy()
    results['if_score']     = if_scores
    results['if_anomaly']   = (if_preds == -1)
    results['ocsvm_score']  = ocsvm_scores
    results['ocsvm_anomaly'] = (ocsvm_preds == -1)
    results['verdict']      = np.where(if_preds == -1, 'ANOMALY', 'NORMAL')

    return results


# ──────────────────────────────────────────────────────────────────────────────
# Alert emission
# ──────────────────────────────────────────────────────────────────────────────

def emit_alerts(scored: pd.DataFrame, verbose: bool = True) -> int:
    """
    Print ANOMALY windows as JSON alert lines to stdout.

    Returns the number of alerts emitted.
    """
    alerts = scored[scored['verdict'] == 'ANOMALY']

    for _, row in alerts.iterrows():
        alert = {
            'window_start':  round(float(row['window_start']), 3),
            'window_index':  int(row['window_index']),
            'phase_true':    str(row['phase']),
            'if_anomaly':    bool(row['if_anomaly']),
            'if_score':      round(float(row['if_score']), 4),
            'ocsvm_anomaly': bool(row['ocsvm_anomaly']),
            'ocsvm_score':   round(float(row['ocsvm_score']), 4),
            'verdict':       str(row['verdict']),
        }
        print(json.dumps(alert))

    if verbose:
        n_total  = len(scored)
        n_alerts = len(alerts)
        log.info('Scored %d windows → %d alerts (%.1f%%)',
                 n_total, n_alerts, 100 * n_alerts / n_total if n_total else 0)

    return len(alerts)


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def run_pipeline(
    session_dir: Path,
    window_seconds: float = DEFAULT_WINDOW_SECONDS,
    save_scores: bool = True,
) -> pd.DataFrame:
    """
    End-to-end pipeline:
      1. Load models
      2. Extract features from session_dir
      3. Score windows
      4. Emit alerts to stdout
      5. Optionally save full scored table

    Returns the scored DataFrame for programmatic use.
    """
    clf_if, clf_ocsvm, scaler = load_models()

    session_id = session_dir.name
    ft = extract_features(session_dir, session_id, window_seconds)

    scored = score_windows(ft, clf_if, clf_ocsvm, scaler)
    emit_alerts(scored)

    if save_scores:
        out_path = OUTPUT_DIR / f'live_scores_{session_id}.parquet'
        scored.to_parquet(out_path, index=False)
        log.info('Full scores saved → %s', out_path)

    return scored


def main() -> None:
    raise SystemExit('Legacy replay retired: use python -m inference.replay --help or python -m inference.streaming --help')
    parser = argparse.ArgumentParser(
        description='Live eBPF IDS inference pipeline'
    )
    parser.add_argument(
        '--session-dir', required=True, type=Path,
        help='Path to a session directory containing execsnoop.csv, '
             'opensnoop.csv, tcpconnect.csv (and optionally phase_log.csv)',
    )
    parser.add_argument(
        '--window', type=float, default=DEFAULT_WINDOW_SECONDS,
        help=f'Window size in seconds (default: {DEFAULT_WINDOW_SECONDS})',
    )
    parser.add_argument(
        '--no-save', action='store_true',
        help='Do not save the full scored table to disk',
    )
    args = parser.parse_args()

    session_dir = args.session_dir.resolve()
    if not session_dir.exists():
        log.error('Session directory not found: %s', session_dir)
        sys.exit(1)

    run_pipeline(session_dir, window_seconds=args.window,
                 save_scores=not args.no_save)


if __name__ == '__main__':
    main()
