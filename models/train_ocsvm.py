"""
models/train_ocsvm.py
-----------------------
WP-08: Train a One-Class SVM anomaly detector on baseline windows.

Training strategy:
  - Input: feature table from feature_engineering/output/features_window5s.parquet
  - Training set: baseline-labelled windows only (from both sessions)
  - Scoring: all 2522 windows (baseline + all attack phases)
  - StandardScaler fit on training (baseline) data ONLY — persisted alongside model
  - Model saved to: models/output/ocsvm.joblib
  - Scaler saved to: models/output/ocsvm_scaler.joblib

Feature columns used (same 7 as Isolation Forest):
    n_exec, n_unique_pcomm,
    n_open, n_unique_paths,      <- log1p versions
    n_open_errors,
    n_tcp_connect, n_unique_daddr

Kernel: RBF — standard choice for non-linear boundary. The nu parameter
controls the upper bound on the fraction of outliers in training data and
the lower bound on the fraction of support vectors.

Usage:
    python models/train_ocsvm.py
"""

from __future__ import annotations
import sys
import logging
from pathlib import Path

import numpy as np
import joblib
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s',
                    datefmt='%H:%M:%S')
log = logging.getLogger(__name__)

# ── paths ────────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from feature_engineering.features import load_features, DEFAULT_WINDOW_SECONDS

OUTPUT_DIR = PROJECT_ROOT / 'models' / 'output'
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

MODEL_PATH  = OUTPUT_DIR / 'ocsvm.joblib'
SCALER_PATH = OUTPUT_DIR / 'ocsvm_scaler.joblib'
SCORES_PATH = OUTPUT_DIR / 'ocsvm_scores.parquet'

# ── feature columns (must match train_isolation_forest.py) ───────────────────
MODEL_FEATURES = [
    'n_exec', 'n_unique_pcomm',
    'n_open', 'n_unique_paths',      # log1p versions
    'n_open_errors',
    'n_tcp_connect', 'n_unique_daddr',
]

# ── hyperparameters ───────────────────────────────────────────────────────────
# nu: upper bound on training-set outlier fraction.
# With clean baseline-only training, nu=0.05 means we allow ≤5% of baseline
# windows to be support vectors (boundary region). Conservative but robust.
OCSVM_PARAMS = dict(
    kernel='rbf',
    nu=0.05,
    gamma='scale',   # gamma = 1 / (n_features * X.var()) — auto-tuned
)


def train(window_seconds: float = DEFAULT_WINDOW_SECONDS) -> dict:
    """
    Load features, scale, train OC-SVM on baseline windows, score all windows.

    Returns a dict with keys: model, scaler, scores_df, metrics
    """
    log.info('Loading feature table (window=%.1fs)…', window_seconds)
    ft = load_features(window_seconds)
    log.info('  Total windows: %d', len(ft))

    # ── split train / eval ────────────────────────────────────────────────────
    train_mask = ft['phase'] == 'baseline'
    X_train_raw = ft.loc[train_mask, MODEL_FEATURES].to_numpy(dtype=float)
    X_all_raw   = ft[MODEL_FEATURES].to_numpy(dtype=float)

    log.info('  Training on %d baseline windows (%.1f%%)',
             X_train_raw.shape[0], 100 * X_train_raw.shape[0] / len(ft))

    # ── scale — fit ONLY on baseline ─────────────────────────────────────────
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train_raw)
    X_all   = scaler.transform(X_all_raw)
    log.info('  StandardScaler fit on baseline only.')

    # ── train ─────────────────────────────────────────────────────────────────
    log.info('Training OneClassSVM(kernel=%s, nu=%.2f, gamma=%s)…',
             OCSVM_PARAMS['kernel'], OCSVM_PARAMS['nu'], OCSVM_PARAMS['gamma'])
    clf = OneClassSVM(**OCSVM_PARAMS)
    clf.fit(X_train)
    log.info('Training complete. Support vectors: %d', clf.n_support_[0])

    # ── score all windows ─────────────────────────────────────────────────────
    # decision_function: positive = inside boundary (normal), negative = anomaly
    # predict: +1 = normal, -1 = anomaly
    raw_scores  = clf.decision_function(X_all)   # shape (N,)
    predictions = clf.predict(X_all)             # +1 or -1

    scores_df = ft[['session_id', 'window_index', 'window_start', 'phase']].copy()
    scores_df['ocsvm_score']   = raw_scores
    scores_df['ocsvm_anomaly'] = (predictions == -1)

    # ── quick evaluation ──────────────────────────────────────────────────────
    y_true = (ft['phase'] != 'baseline') & (ft['phase'] != 'unlabeled')
    y_pred = scores_df['ocsvm_anomaly']

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

    log.info('  Per-phase anomaly rate:')
    for phase in sorted(ft['phase'].unique()):
        mask = ft['phase'] == phase
        rate = scores_df.loc[mask, 'ocsvm_anomaly'].mean()
        log.info('    %-22s  %.1f%%', phase, 100 * rate)

    # ── save ──────────────────────────────────────────────────────────────────
    joblib.dump(clf, MODEL_PATH)
    log.info('Model saved → %s', MODEL_PATH)

    joblib.dump(scaler, SCALER_PATH)
    log.info('Scaler saved → %s', SCALER_PATH)

    scores_df.to_parquet(SCORES_PATH, index=False)
    log.info('Scores saved → %s', SCORES_PATH)

    return dict(model=clf, scaler=scaler, scores_df=scores_df, metrics=metrics)


if __name__ == '__main__':
    result = train()
    log.info('Done. F1=%.3f', result['metrics']['f1'])
