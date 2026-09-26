"""
models/train_isolation_forest.py
----------------------------------
WP-07: Train an Isolation Forest anomaly detector on baseline windows.

Training strategy:
  - Input: feature table from feature_engineering/output/features_window5s.parquet
  - Training set: baseline-labelled windows only (from both sessions)
  - Scoring: all 2522 windows (baseline + all attack phases)
  - Model saved to: models/output/isolation_forest.joblib

Feature columns used (log1p-transformed opensnoop counts):
    n_exec, n_unique_pcomm,
    n_open, n_unique_paths,      <- log1p versions
    n_open_errors,
    n_tcp_connect, n_unique_daddr

No StandardScaler needed — Isolation Forest is scale-invariant (tree-based).

Usage:
    python models/train_isolation_forest.py
"""

from __future__ import annotations
import sys
import logging
from pathlib import Path

import numpy as np
import joblib
from sklearn.ensemble import IsolationForest

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s',
                    datefmt='%H:%M:%S')
log = logging.getLogger(__name__)

# ── paths ────────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from feature_engineering.features import load_features, DEFAULT_WINDOW_SECONDS

OUTPUT_DIR = PROJECT_ROOT / 'models' / 'output'
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

MODEL_PATH = OUTPUT_DIR / 'isolation_forest.joblib'
SCORES_PATH = OUTPUT_DIR / 'if_scores.parquet'

# ── feature columns fed to the model ─────────────────────────────────────────
MODEL_FEATURES = [
    'n_exec', 'n_unique_pcomm',
    'n_open', 'n_unique_paths',      # log1p versions
    'n_open_errors',
    'n_tcp_connect', 'n_unique_daddr',
]

# ── hyperparameters ───────────────────────────────────────────────────────────
# contamination='auto' → sklearn sets threshold at score=-0.5 (standard default)
# Since we train on baseline-only, the training data is clean, so 'auto' is
# appropriate — we don't want to artificially mark baseline windows as anomalous.
IF_PARAMS = dict(
    n_estimators=200,       # more trees → more stable scores
    max_samples='auto',     # subsample size per tree (default: min(256, n_samples))
    contamination='auto',   # threshold: score < -0.5 → anomaly
    random_state=42,
    n_jobs=-1,
)


def train(window_seconds: float = DEFAULT_WINDOW_SECONDS) -> dict:
    """
    Load features, train Isolation Forest on baseline windows, score all windows.

    Returns a dict with keys: model, scores_df, metrics
    """
    log.info('Loading feature table (window=%.1fs)…', window_seconds)
    ft = load_features(window_seconds)
    log.info('  Total windows: %d', len(ft))

    # ── split train / eval ────────────────────────────────────────────────────
    train_mask = ft['phase'] == 'baseline'
    X_train = ft.loc[train_mask, MODEL_FEATURES].to_numpy(dtype=float)
    X_all   = ft[MODEL_FEATURES].to_numpy(dtype=float)

    log.info('  Training on %d baseline windows (%.1f%%)',
             X_train.shape[0], 100 * X_train.shape[0] / len(ft))

    # ── train ─────────────────────────────────────────────────────────────────
    log.info('Training IsolationForest(n_estimators=%d)…', IF_PARAMS['n_estimators'])
    clf = IsolationForest(**IF_PARAMS)
    clf.fit(X_train)
    log.info('Training complete.')

    # ── score all windows ─────────────────────────────────────────────────────
    # score_samples returns the raw anomaly score (lower = more anomalous)
    # predict returns +1 (normal) or -1 (anomaly)
    raw_scores = clf.score_samples(X_all)     # shape (N,)
    predictions = clf.predict(X_all)          # +1 or -1

    scores_df = ft[['session_id', 'window_index', 'window_start', 'phase']].copy()
    scores_df['if_score']     = raw_scores          # raw anomaly score
    scores_df['if_anomaly']   = (predictions == -1) # True = predicted anomaly

    # ── quick evaluation ──────────────────────────────────────────────────────
    # Using phase != 'baseline' as the ground-truth "anomaly" label
    y_true = (ft['phase'] != 'baseline') & (ft['phase'] != 'unlabeled')
    y_pred = scores_df['if_anomaly']

    tp = int((y_true &  y_pred).sum())
    fp = int((~y_true &  y_pred).sum())
    fn = int((y_true & ~y_pred).sum())
    tn = int((~y_true & ~y_pred).sum())

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)

    metrics = dict(tp=tp, fp=fp, fn=fn, tn=tn,
                   precision=precision, recall=recall, f1=f1)

    log.info('── Evaluation (phase != baseline → anomaly) ──────────────')
    log.info('  TP=%d  FP=%d  FN=%d  TN=%d', tp, fp, fn, tn)
    log.info('  Precision=%.3f  Recall=%.3f  F1=%.3f', precision, recall, f1)

    # Per-phase breakdown
    log.info('  Per-phase anomaly rate:')
    for phase in sorted(ft['phase'].unique()):
        mask = ft['phase'] == phase
        rate = scores_df.loc[mask, 'if_anomaly'].mean()
        log.info('    %-22s  %.1f%%', phase, 100 * rate)

    # ── save ──────────────────────────────────────────────────────────────────
    joblib.dump(clf, MODEL_PATH)
    log.info('Model saved → %s', MODEL_PATH)

    scores_df.to_parquet(SCORES_PATH, index=False)
    log.info('Scores saved → %s', SCORES_PATH)

    return dict(model=clf, scores_df=scores_df, metrics=metrics)


if __name__ == '__main__':
    result = train()
    log.info('Done. F1=%.3f', result['metrics']['f1'])
