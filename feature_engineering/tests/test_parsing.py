"""
feature_engineering/tests/test_parsing.py
------------------------------------------
Unit tests for the three raw-log loaders in parsing.py.

Uses small hand-crafted fixture strings (not the real multi-million-row
files) to verify:
  - Header lines are detected and skipped
  - Timestamps are parsed as floats
  - Numeric columns are coerced correctly
  - Trailing columns with embedded spaces (ARGS / PATH) are preserved
  - Row counts match (header excluded)
  - No NaN in required numeric columns
"""

import io
import textwrap
from pathlib import Path

import pandas as pd
import pytest

# Make sure we can import the module regardless of CWD
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from feature_engineering.parsing import load_execsnoop, load_opensnoop, load_tcpconnect


# ──────────────────────────────────────────────────────────────────────────────
# Fixtures — representative lines from real files, kept tiny for fast tests
# ──────────────────────────────────────────────────────────────────────────────

EXECSNOOP_FIXTURE = textwrap.dedent("""\
    1789367652.100637,PCOMM            PID    PPID   RET ARGS
    1789367654.862810,sleep            6876   6858     0 /usr/bin/sleep 3600
    1789367941.104140,9                6914   1        0 /proc/self/fd/9 --deserialize 161 --log-level info
    1789367941.121799,systemd-tmpfile  6914   1        0 /usr/bin/systemd-tmpfiles --clean
    1789368011.421279,bash             6925   6900     0 /bin/bash -c echo hello world
""")

OPENSNOOP_FIXTURE = textwrap.dedent("""\
    1789367652.108014,PID    COMM              FD ERR PATH
    1789367652.108216,6870   opensnoop         24   0 /sys/kernel/debug/tracing/events/syscalls/sys_exit_openat2/id
    1789367652.108279,6870   opensnoop         27   0 /etc/localtime
    1789367652.169365,4432   gvfs-udisks2-vo   14   0 /proc/self/mountinfo
    1789367652.169679,4432   gvfs-udisks2-vo   14  -1 /run/mount/utab with spaces in path
""")

TCPCONNECT_FIXTURE = textwrap.dedent("""\
    1789367652.108692,PID    COMM             IP SADDR            DADDR            DPORT
    1789367685.903794,1656   NetworkManager   4  192.168.1.9      91.189.91.97     80
    1789367686.105048,1656   NetworkManager   4  192.168.1.9      91.189.91.62     80
    1789367686.900954,1656   NetworkManager   6  2401:4900::1     2620:2d:4000::1  443
""")

# Real-world fixture: COMM contains a space (e.g. thread name with number)
OPENSNOOP_MULTIWORD_COMM_FIXTURE = textwrap.dedent("""\
    1789367652.108014,PID    COMM              FD ERR PATH
    1789367658.666062,5293   StreamT~ns #132  129   0 /proc/self/statm
    1789367658.669384,5293   StreamT~ns #123  133   0 /proc/self/smaps
    1789367666.694648,5293   BgIOThr~Pool #8  129   0 /home/srinath/snap/firefox/common/.mozilla/firefox/cbw7tobg.default/extensions
""")


def _write_tmp(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding='utf-8')
    return p


# ──────────────────────────────────────────────────────────────────────────────
# execsnoop tests
# ──────────────────────────────────────────────────────────────────────────────

class TestLoadExecsnoop:

    def test_row_count_excludes_header(self, tmp_path):
        path = _write_tmp(tmp_path, 'execsnoop.csv', EXECSNOOP_FIXTURE)
        df = load_execsnoop(path)
        # fixture has 1 header + 4 data rows
        assert len(df) == 4, f"Expected 4 rows, got {len(df)}"

    def test_columns_present(self, tmp_path):
        path = _write_tmp(tmp_path, 'execsnoop.csv', EXECSNOOP_FIXTURE)
        df = load_execsnoop(path)
        assert list(df.columns) == ['timestamp', 'pcomm', 'pid', 'ppid', 'ret', 'args']

    def test_timestamp_is_float(self, tmp_path):
        path = _write_tmp(tmp_path, 'execsnoop.csv', EXECSNOOP_FIXTURE)
        df = load_execsnoop(path)
        assert df['timestamp'].dtype == float
        assert df['timestamp'].iloc[0] == pytest.approx(1789367654.862810)

    def test_numeric_columns_no_nan(self, tmp_path):
        path = _write_tmp(tmp_path, 'execsnoop.csv', EXECSNOOP_FIXTURE)
        df = load_execsnoop(path)
        for col in ('pid', 'ppid', 'ret'):
            assert df[col].isna().sum() == 0, f"NaN found in {col}"

    def test_pid_parsed_correctly(self, tmp_path):
        path = _write_tmp(tmp_path, 'execsnoop.csv', EXECSNOOP_FIXTURE)
        df = load_execsnoop(path)
        assert df['pid'].iloc[0] == 6876

    def test_args_preserves_spaces(self, tmp_path):
        path = _write_tmp(tmp_path, 'execsnoop.csv', EXECSNOOP_FIXTURE)
        df = load_execsnoop(path)
        # Last row: args = "/bin/bash -c echo hello world"
        assert 'hello world' in df['args'].iloc[-1]

    def test_multiword_args_in_third_row(self, tmp_path):
        path = _write_tmp(tmp_path, 'execsnoop.csv', EXECSNOOP_FIXTURE)
        df = load_execsnoop(path)
        # Second data row has multi-token ARGS
        assert '--deserialize' in df['args'].iloc[1]


# ──────────────────────────────────────────────────────────────────────────────
# opensnoop tests
# ──────────────────────────────────────────────────────────────────────────────

class TestLoadOpensnoop:

    def test_row_count_excludes_header(self, tmp_path):
        path = _write_tmp(tmp_path, 'opensnoop.csv', OPENSNOOP_FIXTURE)
        df = load_opensnoop(path)
        assert len(df) == 4, f"Expected 4 rows, got {len(df)}"

    def test_columns_present(self, tmp_path):
        path = _write_tmp(tmp_path, 'opensnoop.csv', OPENSNOOP_FIXTURE)
        df = load_opensnoop(path)
        assert list(df.columns) == ['timestamp', 'pid', 'comm', 'fd', 'err', 'path']

    def test_timestamp_is_float(self, tmp_path):
        path = _write_tmp(tmp_path, 'opensnoop.csv', OPENSNOOP_FIXTURE)
        df = load_opensnoop(path)
        assert df['timestamp'].dtype == float

    def test_numeric_columns_no_nan(self, tmp_path):
        path = _write_tmp(tmp_path, 'opensnoop.csv', OPENSNOOP_FIXTURE)
        df = load_opensnoop(path)
        for col in ('pid', 'fd', 'err'):
            assert df[col].isna().sum() == 0, f"NaN found in {col}"

    def test_err_column_handles_negative(self, tmp_path):
        path = _write_tmp(tmp_path, 'opensnoop.csv', OPENSNOOP_FIXTURE)
        df = load_opensnoop(path)
        # Last row has err=-1
        assert df['err'].iloc[-1] == -1

    def test_path_preserves_spaces(self, tmp_path):
        path = _write_tmp(tmp_path, 'opensnoop.csv', OPENSNOOP_FIXTURE)
        df = load_opensnoop(path)
        # Last row: path = "/run/mount/utab with spaces in path"
        assert 'spaces in path' in df['path'].iloc[-1]


# ──────────────────────────────────────────────────────────────────────────────
# tcpconnect tests
# ──────────────────────────────────────────────────────────────────────────────

class TestLoadTcpconnect:

    def test_row_count_excludes_header(self, tmp_path):
        path = _write_tmp(tmp_path, 'tcpconnect.csv', TCPCONNECT_FIXTURE)
        df = load_tcpconnect(path)
        assert len(df) == 3, f"Expected 3 rows, got {len(df)}"

    def test_columns_present(self, tmp_path):
        path = _write_tmp(tmp_path, 'tcpconnect.csv', TCPCONNECT_FIXTURE)
        df = load_tcpconnect(path)
        assert list(df.columns) == ['timestamp', 'pid', 'comm', 'ip', 'saddr', 'daddr', 'dport']

    def test_numeric_columns_no_nan(self, tmp_path):
        path = _write_tmp(tmp_path, 'tcpconnect.csv', TCPCONNECT_FIXTURE)
        df = load_tcpconnect(path)
        for col in ('pid', 'ip', 'dport'):
            assert df[col].isna().sum() == 0, f"NaN found in {col}"

    def test_ipv4_and_ipv6_parsed(self, tmp_path):
        path = _write_tmp(tmp_path, 'tcpconnect.csv', TCPCONNECT_FIXTURE)
        df = load_tcpconnect(path)
        assert set(df['ip'].unique()) == {4, 6}

    def test_dport_values(self, tmp_path):
        path = _write_tmp(tmp_path, 'tcpconnect.csv', TCPCONNECT_FIXTURE)
        df = load_tcpconnect(path)
        assert list(df['dport']) == [80, 80, 443]


# ──────────────────────────────────────────────────────────────────────────────
# Regression: multi-word COMM values (found in real session data)
# ──────────────────────────────────────────────────────────────────────────────

TCPCONNECT_MULTIWORD_COMM_FIXTURE = textwrap.dedent("""\
    1789565203.930412,PID    COMM             IP SADDR            DADDR            DPORT
    1789565206.539604,20814  Socket Thread    6  2401:4900:1ce2:9be:5992:c02a:511:a0c0 2600:140f:6:6a3::24e8 443
    1789565213.229621,20814  Socket Thread    6  2401:4900:1ce2:9be:5992:c02a:511:a0c0 2001:4860:4828:400:: 443
    1789565218.280054,20814  Socket Thread    6  2401:4900:1ce2:9be:5992:c02a:511:a0c0 2404:6800:4007:808::2002 443
    1789367685.903794,1656   NetworkManager   4  192.168.1.9      91.189.91.97     80
""")


class TestMultiWordCommOpensnoop:
    """Regression tests for COMM values with embedded spaces in opensnoop."""

    def test_row_count(self, tmp_path):
        path = _write_tmp(tmp_path, 'opensnoop.csv', OPENSNOOP_MULTIWORD_COMM_FIXTURE)
        df = load_opensnoop(path)
        assert len(df) == 3, f"Expected 3 rows, got {len(df)}"

    def test_no_nan_in_fd(self, tmp_path):
        path = _write_tmp(tmp_path, 'opensnoop.csv', OPENSNOOP_MULTIWORD_COMM_FIXTURE)
        df = load_opensnoop(path)
        assert df['fd'].isna().sum() == 0, "NaN found in fd — multi-word COMM not handled"

    def test_no_nan_in_err(self, tmp_path):
        path = _write_tmp(tmp_path, 'opensnoop.csv', OPENSNOOP_MULTIWORD_COMM_FIXTURE)
        df = load_opensnoop(path)
        assert df['err'].isna().sum() == 0, "NaN found in err — multi-word COMM not handled"

    def test_comm_includes_thread_number(self, tmp_path):
        path = _write_tmp(tmp_path, 'opensnoop.csv', OPENSNOOP_MULTIWORD_COMM_FIXTURE)
        df = load_opensnoop(path)
        # COMM should be "StreamT~ns #132", not just "StreamT~ns"
        assert '#132' in df['comm'].iloc[0], f"Thread number lost in COMM: {df['comm'].iloc[0]}"

    def test_fd_values_correct(self, tmp_path):
        path = _write_tmp(tmp_path, 'opensnoop.csv', OPENSNOOP_MULTIWORD_COMM_FIXTURE)
        df = load_opensnoop(path)
        assert list(df['fd']) == [129, 133, 129]

    def test_err_values_correct(self, tmp_path):
        path = _write_tmp(tmp_path, 'opensnoop.csv', OPENSNOOP_MULTIWORD_COMM_FIXTURE)
        df = load_opensnoop(path)
        assert list(df['err']) == [0, 0, 0]


class TestMultiWordCommTcpconnect:
    """Regression tests for COMM values with embedded spaces in tcpconnect."""

    def test_row_count(self, tmp_path):
        path = _write_tmp(tmp_path, 'tcpconnect.csv', TCPCONNECT_MULTIWORD_COMM_FIXTURE)
        df = load_tcpconnect(path)
        assert len(df) == 4, f"Expected 4 rows, got {len(df)}"

    def test_no_nan_in_ip(self, tmp_path):
        path = _write_tmp(tmp_path, 'tcpconnect.csv', TCPCONNECT_MULTIWORD_COMM_FIXTURE)
        df = load_tcpconnect(path)
        assert df['ip'].isna().sum() == 0, "NaN found in ip — multi-word COMM not handled"

    def test_comm_is_socket_thread(self, tmp_path):
        path = _write_tmp(tmp_path, 'tcpconnect.csv', TCPCONNECT_MULTIWORD_COMM_FIXTURE)
        df = load_tcpconnect(path)
        assert df['comm'].iloc[0] == 'Socket Thread', f"COMM wrong: {df['comm'].iloc[0]}"

    def test_ip_versions_correct(self, tmp_path):
        path = _write_tmp(tmp_path, 'tcpconnect.csv', TCPCONNECT_MULTIWORD_COMM_FIXTURE)
        df = load_tcpconnect(path)
        assert list(df['ip']) == [6, 6, 6, 4]

    def test_dport_values_correct(self, tmp_path):
        path = _write_tmp(tmp_path, 'tcpconnect.csv', TCPCONNECT_MULTIWORD_COMM_FIXTURE)
        df = load_tcpconnect(path)
        assert list(df['dport']) == [443, 443, 443, 80]
