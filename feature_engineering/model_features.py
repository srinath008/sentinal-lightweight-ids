"""Stateless features derived identically during training and inference."""
import numpy as np


def behavioural_features(values):
    """Log activity counts and add rates; input order is events.FEATURES."""
    x = np.asarray(values, dtype=float)
    if x.ndim != 2 or x.shape[1] != 7 or not np.isfinite(x).all() or (x < 0).any():
        raise ValueError('Expected finite nonnegative seven-column features')
    execution, processes, opens, paths, errors, tcp, destinations = x.T
    raw_opens, raw_paths = np.expm1(opens), np.expm1(paths)
    return np.column_stack([
        np.log1p(execution), np.log1p(processes), opens, paths,
        np.log1p(errors), np.log1p(tcp), np.log1p(destinations),
        errors / (raw_opens + 1), raw_paths / (raw_opens + 1),
        processes / (execution + 1), tcp / (destinations + 1),
    ])
