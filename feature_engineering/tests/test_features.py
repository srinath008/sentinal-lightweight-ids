"""
feature_engineering/tests/test_features.py
-------------------------------------------
Unit tests for the windowed feature engineering module (features.py).

Uses synthetic labeled DataFrames (not the real 8M-row files) to verify:
  - Correct window bucketing for all three event sources
  - Correct zero-filling for windows with no events from a given source
  - log1p applied to n_open and n_unique_paths (not to raw counts)
  - Phase label carried through correctly
  - Session independence (windows never span two sessions)
  - Expected column set and dtypes
  - Approximate row count (session_duration / window_seconds)
"""

from pathlib import Path
import numpy as np
import pandas as pd
import pytest
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from feature_engineering.features import (
    build_feature_table,
    _assign_window_index,
    DEFAULT_WINDOW_SECONDS,
)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _make_exec(timestamps, pcomms, session='s1', phase='baseline'):
    return pd.DataFrame({
        'timestamp': timestamps,
        'pcomm':     pcomms,
        'pid':       [100] * len(timestamps),
        'ppid':      [1]   * len(timestamps),
        'ret':       [0]   * len(timestamps),
        'args':      ['']  * len(timestamps),
        'session_id': session,
        'phase':     phase,
    })


def _make_open(timestamps, paths, errs=None, session='s1', phase='baseline'):
    if errs is None:
        errs = [0] * len(timestamps)
    return pd.DataFrame({
        'timestamp': timestamps,
        'pid':       [100] * len(timestamps),
        'comm':      ['proc'] * len(timestamps),
        'fd':        [3] * len(timestamps),
        'err':       errs,
        'path':      paths,
        'session_id': session,
        'phase':     phase,
    })


def _make_tcp(timestamps, daddrs, session='s1', phase='baseline'):
    return pd.DataFrame({
        'timestamp': timestamps,
        'pid':       [100] * len(timestamps),
        'comm':      ['proc'] * len(timestamps),
        'ip':        [4] * len(timestamps),
        'saddr':     ['127.0.0.1'] * len(timestamps),
        'daddr':     daddrs,
        'dport':     [80] * len(timestamps),
        'session_id': session,
        'phase':     phase,
    })


# ──────────────────────────────────────────────────────────────────────────────
# _assign_window_index tests
# ──────────────────────────────────────────────────────────────────────────────

class TestAssignWindowIndex:

    def test_all_same_window(self):
        ts = pd.Series([1000.0, 1001.0, 1004.9])
        idx = _assign_window_index(ts, 5.0)
        assert list(idx) == [0, 0, 0]

    def test_two_windows(self):
        ts = pd.Series([1000.0, 1005.0])
        idx = _assign_window_index(ts, 5.0)
        assert list(idx) == [0, 1]

    def test_window_boundary_is_start_of_next(self):
        # t=1005.0 exactly is window 1 (floor((1005-1000)/5) = floor(1.0) = 1)
        ts = pd.Series([1000.0, 1004.999, 1005.0])
        idx = _assign_window_index(ts, 5.0)
        assert list(idx) == [0, 0, 1]

    def test_single_event(self):
        ts = pd.Series([1234.5])
        idx = _assign_window_index(ts, 5.0)
        assert list(idx) == [0]

    def test_different_window_size(self):
        ts = pd.Series([0.0, 9.9, 10.0, 19.9])
        idx = _assign_window_index(ts, 10.0)
        assert list(idx) == [0, 0, 1, 1]


# ──────────────────────────────────────────────────────────────────────────────
# build_feature_table tests
# ──────────────────────────────────────────────────────────────────────────────

class TestBuildFeatureTable:

    # Minimal synthetic data: 3 exec events in window 0, 2 in window 1
    # 5 open events spread across 2 windows, 1 tcp event in window 0
    T0 = 1000.0

    def _make_minimal_dfs(self, session='s1'):
        exec_df = _make_exec(
            [self.T0, self.T0+1, self.T0+2,    # window 0
             self.T0+5, self.T0+6],             # window 1
            ['bash', 'ls', 'bash', 'curl', 'wget'],
            session=session,
        )
        open_df = _make_open(
            [self.T0, self.T0+1, self.T0+2, self.T0+3,   # window 0
             self.T0+5],                                   # window 1
            ['/etc/passwd', '/etc/hosts', '/etc/passwd', '/tmp/x',
             '/etc/resolv.conf'],
            errs=[0, 0, 0, 1, 0],
            session=session,
        )
        tcp_df = _make_tcp(
            [self.T0+2],        # window 0
            ['8.8.8.8'],
            session=session,
        )
        return exec_df, open_df, tcp_df

    def test_output_columns(self):
        exec_df, open_df, tcp_df = self._make_minimal_dfs()
        ft = build_feature_table(exec_df, open_df, tcp_df, window_seconds=5.0)
        expected = {
            'session_id', 'window_index', 'window_start', 'phase',
            'n_exec', 'n_unique_pcomm',
            'n_open_raw', 'n_unique_paths_raw', 'n_open_errors',
            'n_open', 'n_unique_paths',
            'n_tcp_connect', 'n_unique_daddr',
        }
        assert set(ft.columns) == expected

    def test_two_windows_produced(self):
        exec_df, open_df, tcp_df = self._make_minimal_dfs()
        ft = build_feature_table(exec_df, open_df, tcp_df, window_seconds=5.0)
        assert len(ft) == 2, f"Expected 2 windows, got {len(ft)}"

    def test_n_exec_counts(self):
        exec_df, open_df, tcp_df = self._make_minimal_dfs()
        ft = build_feature_table(exec_df, open_df, tcp_df, window_seconds=5.0).sort_values('window_index')
        assert ft['n_exec'].tolist() == [3, 2]

    def test_n_unique_pcomm(self):
        exec_df, open_df, tcp_df = self._make_minimal_dfs()
        ft = build_feature_table(exec_df, open_df, tcp_df, window_seconds=5.0).sort_values('window_index')
        # window 0: bash, ls, bash → 2 unique; window 1: curl, wget → 2 unique
        assert ft['n_unique_pcomm'].tolist() == [2, 2]

    def test_n_open_raw_counts(self):
        exec_df, open_df, tcp_df = self._make_minimal_dfs()
        ft = build_feature_table(exec_df, open_df, tcp_df, window_seconds=5.0).sort_values('window_index')
        assert ft['n_open_raw'].tolist() == [4, 1]

    def test_n_unique_paths(self):
        exec_df, open_df, tcp_df = self._make_minimal_dfs()
        ft = build_feature_table(exec_df, open_df, tcp_df, window_seconds=5.0).sort_values('window_index')
        # window 0: /etc/passwd (x2), /etc/hosts, /tmp/x → 3 unique raw paths
        assert ft['n_unique_paths_raw'].tolist() == [3, 1]

    def test_n_open_errors(self):
        exec_df, open_df, tcp_df = self._make_minimal_dfs()
        ft = build_feature_table(exec_df, open_df, tcp_df, window_seconds=5.0).sort_values('window_index')
        # window 0 has 1 error (err=1); window 1 has 0
        assert ft['n_open_errors'].tolist() == [1, 0]

    def test_n_tcp_connect(self):
        exec_df, open_df, tcp_df = self._make_minimal_dfs()
        ft = build_feature_table(exec_df, open_df, tcp_df, window_seconds=5.0).sort_values('window_index')
        # window 0: 1 tcp event; window 1: 0
        assert ft['n_tcp_connect'].tolist() == [1, 0]

    def test_zero_fill_tcp_in_window1(self):
        """Window 1 has no TCP events — must appear as 0, not NaN or dropped."""
        exec_df, open_df, tcp_df = self._make_minimal_dfs()
        ft = build_feature_table(exec_df, open_df, tcp_df, window_seconds=5.0).sort_values('window_index')
        assert ft['n_tcp_connect'].iloc[1] == 0
        assert ft['n_unique_daddr'].iloc[1] == 0

    def test_log1p_applied_to_n_open(self):
        """n_open must equal log1p(n_open_raw), not the raw count."""
        exec_df, open_df, tcp_df = self._make_minimal_dfs()
        ft = build_feature_table(exec_df, open_df, tcp_df, window_seconds=5.0).sort_values('window_index')
        expected = np.log1p(ft['n_open_raw'])
        np.testing.assert_allclose(ft['n_open'].values, expected.values, rtol=1e-9)

    def test_log1p_applied_to_n_unique_paths(self):
        exec_df, open_df, tcp_df = self._make_minimal_dfs()
        ft = build_feature_table(exec_df, open_df, tcp_df, window_seconds=5.0).sort_values('window_index')
        expected = np.log1p(ft['n_unique_paths_raw'])
        np.testing.assert_allclose(ft['n_unique_paths'].values, expected.values, rtol=1e-9)

    def test_phase_label_carried_through(self):
        exec_df, open_df, tcp_df = self._make_minimal_dfs()
        ft = build_feature_table(exec_df, open_df, tcp_df, window_seconds=5.0)
        assert (ft['phase'] == 'baseline').all()

    def test_session_id_carried_through(self):
        exec_df, open_df, tcp_df = self._make_minimal_dfs(session='20260914_120411')
        ft = build_feature_table(exec_df, open_df, tcp_df, window_seconds=5.0)
        assert (ft['session_id'] == '20260914_120411').all()

    def test_different_window_size(self):
        """Using 10s windows should halve the number of windows."""
        exec_df, open_df, tcp_df = self._make_minimal_dfs()
        ft_5s  = build_feature_table(exec_df, open_df, tcp_df, window_seconds=5.0)
        ft_10s = build_feature_table(exec_df, open_df, tcp_df, window_seconds=10.0)
        # All our synthetic events span T0 to T0+6, so 10s window collapses to 1
        assert len(ft_10s) == 1
        assert len(ft_5s)  == 2

    def test_session_independence(self):
        """Two sessions must not share window indices."""
        exec1, open1, tcp1 = self._make_minimal_dfs(session='sess_a')
        exec2, open2, tcp2 = self._make_minimal_dfs(session='sess_b')
        exec_df = pd.concat([exec1, exec2], ignore_index=True)
        open_df = pd.concat([open1, open2], ignore_index=True)
        tcp_df  = pd.concat([tcp1,  tcp2],  ignore_index=True)
        ft = build_feature_table(exec_df, open_df, tcp_df, window_seconds=5.0)
        # Each session should have 2 windows independently
        assert len(ft) == 4
        assert set(ft['session_id'].unique()) == {'sess_a', 'sess_b'}

    def test_no_nan_in_feature_columns(self):
        exec_df, open_df, tcp_df = self._make_minimal_dfs()
        ft = build_feature_table(exec_df, open_df, tcp_df, window_seconds=5.0)
        feat_cols = [
            'n_exec', 'n_unique_pcomm', 'n_open_raw', 'n_unique_paths_raw',
            'n_open_errors', 'n_open', 'n_unique_paths', 'n_tcp_connect', 'n_unique_daddr',
        ]
        for col in feat_cols:
            assert ft[col].isna().sum() == 0, f"NaN found in {col}"

    def test_empty_tcp_df(self):
        """Feature table must still work if tcpconnect has zero events."""
        exec_df, open_df, _ = self._make_minimal_dfs()
        empty_tcp = _make_tcp([], [])
        ft = build_feature_table(exec_df, open_df, empty_tcp, window_seconds=5.0)
        assert len(ft) > 0
        assert (ft['n_tcp_connect'] == 0).all()
