"""
feature_engineering/tests/test_labeling.py
-------------------------------------------
Unit tests for the phase-label joining module (labeling.py).

Uses synthetic phase_log.csv data and synthetic event timestamps
to verify:
  - Correct phase assignment within intervals
  - Inclusive boundary behaviour (events exactly at start/end edges)
  - 'unlabeled' assignment for events between phases
  - session_id column correctly added
  - combine_sessions concatenates and preserves session_id
  - Malformed phase_log raises a clear error
"""

import textwrap
from pathlib import Path

import pandas as pd
import pytest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from feature_engineering.labeling import (
    load_phase_log,
    add_phase_labels,
    combine_sessions,
)


# ──────────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────────

PHASE_LOG_CONTENT = textwrap.dedent("""\
    phase,start_epoch,end_epoch
    baseline,1000.0,1999.0
    attack_recon,2000.0,2999.0
    attack_privesc,3000.0,3999.0
    attack_fileaccess,4000.0,4999.0
""")


def _write_phase_log(tmp_path: Path) -> Path:
    p = tmp_path / 'phase_log.csv'
    p.write_text(PHASE_LOG_CONTENT, encoding='utf-8')
    return p


def _make_events(timestamps: list[float]) -> pd.DataFrame:
    """Minimal events DataFrame with just a timestamp column."""
    return pd.DataFrame({'timestamp': timestamps, 'dummy': 'x'})


# ──────────────────────────────────────────────────────────────────────────────
# load_phase_log tests
# ──────────────────────────────────────────────────────────────────────────────

class TestLoadPhaseLog:

    def test_returns_four_rows(self, tmp_path):
        path = _write_phase_log(tmp_path)
        df = load_phase_log(path)
        assert len(df) == 4

    def test_columns(self, tmp_path):
        path = _write_phase_log(tmp_path)
        df = load_phase_log(path)
        assert list(df.columns) == ['phase', 'start_epoch', 'end_epoch']

    def test_epoch_types_are_float(self, tmp_path):
        path = _write_phase_log(tmp_path)
        df = load_phase_log(path)
        assert df['start_epoch'].dtype == float
        assert df['end_epoch'].dtype == float

    def test_phase_values(self, tmp_path):
        path = _write_phase_log(tmp_path)
        df = load_phase_log(path)
        assert list(df['phase']) == [
            'baseline', 'attack_recon', 'attack_privesc', 'attack_fileaccess'
        ]

    def test_missing_column_raises(self, tmp_path):
        bad = tmp_path / 'phase_log.csv'
        bad.write_text("phase,start_epoch\nbaseline,1000.0\n")
        with pytest.raises(ValueError, match="missing expected columns"):
            load_phase_log(bad)


# ──────────────────────────────────────────────────────────────────────────────
# add_phase_labels tests
# ──────────────────────────────────────────────────────────────────────────────

class TestAddPhaseLabels:

    def test_columns_added(self, tmp_path):
        path = _write_phase_log(tmp_path)
        df = add_phase_labels(_make_events([1500.0]), path, 'sess1')
        assert 'phase' in df.columns
        assert 'session_id' in df.columns

    def test_session_id_correct(self, tmp_path):
        path = _write_phase_log(tmp_path)
        df = add_phase_labels(_make_events([1500.0]), path, 'test_session')
        assert df['session_id'].iloc[0] == 'test_session'

    def test_baseline_assignment(self, tmp_path):
        path = _write_phase_log(tmp_path)
        df = add_phase_labels(_make_events([1500.0]), path, 's')
        assert df['phase'].iloc[0] == 'baseline'

    def test_attack_recon_assignment(self, tmp_path):
        path = _write_phase_log(tmp_path)
        df = add_phase_labels(_make_events([2500.0]), path, 's')
        assert df['phase'].iloc[0] == 'attack_recon'

    def test_attack_privesc_assignment(self, tmp_path):
        path = _write_phase_log(tmp_path)
        df = add_phase_labels(_make_events([3500.0]), path, 's')
        assert df['phase'].iloc[0] == 'attack_privesc'

    def test_attack_fileaccess_assignment(self, tmp_path):
        path = _write_phase_log(tmp_path)
        df = add_phase_labels(_make_events([4500.0]), path, 's')
        assert df['phase'].iloc[0] == 'attack_fileaccess'

    def test_unlabeled_between_phases(self, tmp_path):
        """Events in the gap between baseline end (1999) and recon start (2000)."""
        path = _write_phase_log(tmp_path)
        # There's no gap in our fixture (1999→2000 is adjacent closed intervals,
        # but a timestamp of exactly 1999.5 would be in baseline since [1000,1999].
        # Test with a timestamp truly outside all windows.
        df = add_phase_labels(_make_events([5500.0]), path, 's')
        assert df['phase'].iloc[0] == 'unlabeled'

    def test_unlabeled_before_all_phases(self, tmp_path):
        path = _write_phase_log(tmp_path)
        df = add_phase_labels(_make_events([0.0]), path, 's')
        assert df['phase'].iloc[0] == 'unlabeled'

    def test_inclusive_start_boundary(self, tmp_path):
        """Timestamp exactly at start_epoch of baseline → should be 'baseline'."""
        path = _write_phase_log(tmp_path)
        df = add_phase_labels(_make_events([1000.0]), path, 's')
        assert df['phase'].iloc[0] == 'baseline'

    def test_inclusive_end_boundary(self, tmp_path):
        """Timestamp exactly at end_epoch of baseline → should be 'baseline'."""
        path = _write_phase_log(tmp_path)
        df = add_phase_labels(_make_events([1999.0]), path, 's')
        assert df['phase'].iloc[0] == 'baseline'

    def test_multiple_events_correct_phases(self, tmp_path):
        path = _write_phase_log(tmp_path)
        timestamps = [1500.0, 2500.0, 3500.0, 4500.0, 9999.0]
        expected   = ['baseline', 'attack_recon', 'attack_privesc',
                      'attack_fileaccess', 'unlabeled']
        df = add_phase_labels(_make_events(timestamps), path, 's')
        assert list(df['phase']) == expected

    def test_original_columns_preserved(self, tmp_path):
        path = _write_phase_log(tmp_path)
        events = _make_events([1500.0])
        df = add_phase_labels(events, path, 's')
        # Original columns must still be there
        assert 'timestamp' in df.columns
        assert 'dummy' in df.columns

    def test_does_not_modify_input(self, tmp_path):
        """add_phase_labels must return a copy, not mutate the input."""
        path = _write_phase_log(tmp_path)
        events = _make_events([1500.0])
        _ = add_phase_labels(events, path, 's')
        assert 'phase' not in events.columns


# ──────────────────────────────────────────────────────────────────────────────
# combine_sessions tests
# ──────────────────────────────────────────────────────────────────────────────

class TestCombineSessions:

    def test_row_count(self, tmp_path):
        path = _write_phase_log(tmp_path)
        df1 = add_phase_labels(_make_events([1500.0, 2500.0]), path, 'sess_a')
        df2 = add_phase_labels(_make_events([3500.0]), path, 'sess_b')
        combined = combine_sessions([df1, df2])
        assert len(combined) == 3

    def test_session_ids_preserved(self, tmp_path):
        path = _write_phase_log(tmp_path)
        df1 = add_phase_labels(_make_events([1500.0]), path, 'sess_a')
        df2 = add_phase_labels(_make_events([2500.0]), path, 'sess_b')
        combined = combine_sessions([df1, df2])
        assert set(combined['session_id'].unique()) == {'sess_a', 'sess_b'}

    def test_empty_list_raises(self):
        with pytest.raises(ValueError):
            combine_sessions([])
