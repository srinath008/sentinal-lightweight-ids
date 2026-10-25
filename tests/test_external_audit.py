import zipfile
import pytest
from feature_engineering.audit_lidds import audit, recording_lines


def test_audit_preserves_direction_and_reports_missing_and_bad_rows():
    rows = ['1000000000 0 4 sh 4 open > name=L3RtcA==\n',
            '1000000001 0 4 sh 4 open < res=-2\n',
            'bad row\n', '999999999 0 4 sh 4 connect >\n']
    report = audit(rows)
    assert report['counts'] == dict(lines=4, parsed=3, entry=2, out_of_order=1, exit=1, malformed=1)
    assert report['parameter_names']['open<'] == ['res']
    assert report['approved_for_native_training'] is False
    assert audit(rows, 1)['counts']['lines'] == 1


def test_zip_stream_and_ambiguous_recordings(tmp_path):
    path = tmp_path / 'run.zip'
    with zipfile.ZipFile(path, 'w') as archive:
        archive.writestr('run.sc', '100 0 1 sh 1 execve < res=0\n')
    with recording_lines(path) as stream:
        assert audit(stream)['counts']['exit'] == 1
    with zipfile.ZipFile(path, 'a') as archive:
        archive.writestr('other.sc', '')
    with pytest.raises(ValueError), recording_lines(path):
        pass


def test_invalid_limit_and_direction():
    with pytest.raises(ValueError):
        audit([], 0)
    assert audit(['1 0 1 sh 1 open ?'])['counts']['malformed'] == 1
