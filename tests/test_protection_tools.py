import io
import json
from types import SimpleNamespace
from desktop.service import Service
from desktop.scanner import Scanner
from inference.evidence import EvidenceWindow
from feature_engineering.events import Window


def test_export_creates_unique_readable_reports_and_escapes_content(tmp_path):
    service = Service(data_dir=tmp_path/'state', report_dir=tmp_path/'reports')
    service.record(dict(type='error', message='<script>bad</script>'))
    first = service.export_report()
    second = service.export_report()
    assert first['saved_files'] != second['saved_files']
    from pathlib import Path
    report = json.loads(Path(first['saved_files'][0]).read_text())
    assert report['history'][0]['message'] == '<script>bad</script>'
    page = Path(first['saved_files'][1]).read_text()
    assert '<script>bad</script>' not in page
    assert '&lt;script&gt;bad&lt;/script&gt;' in page
    service.close()


def test_live_evidence_is_bounded_and_does_not_change_model_features():
    from feature_engineering.events import FEATURES
    live, plain = EvidenceWindow(), Window()
    for i in range(250):
        event = dict(pid=i, comm='worker', fd=3, err=0, path='/tmp/'+str(i))
        live.add('opensnoop', event)
        plain.add('opensnoop', event)
    row, base = live.row('live',0,0,5), plain.row('live',0,0,5)
    assert [row[k] for k in FEATURES] == [base[k] for k in FEATURES]
    assert row['evidence']['truncated']
    assert len(row['evidence']['processes']) == 5
    assert len(row['evidence']['sample_paths']) == 5


def test_scanner_parses_detections_and_errors_without_deleting_files():
    scanner = Scanner(lambda _: None)
    scanner.result = dict(scanned=0, skipped=0, detections=[])
    scanner._read(SimpleNamespace(stdout=io.StringIO('/tmp/a: Win.Test.EICAR_HDB-1 FOUND\n/tmp/b: OK\n/tmp/c: Permission denied ERROR\n')), [])
    assert scanner.result['scanned'] == 2
    assert scanner.result['skipped'] == 1
    assert scanner.result['detections'][0]['path'] == '/tmp/a'
    assert scanner.result['detections'][0]['kind'] == 'signature detection'


def test_scanner_counts_detections_beyond_the_display_limit():
    scanner = Scanner(lambda _: None)
    scanner._read(SimpleNamespace(stdout=io.StringIO(''.join(
        f'/tmp/sample-{i}: Test.Signature FOUND\n' for i in range(55)))), [])
    assert scanner.result['scanned'] == 55
    assert scanner.result['detection_count'] == 55
    assert len(scanner.result['detections']) == 50


def test_incident_explanation_and_notification_policy(tmp_path, monkeypatch):
    service = Service(data_dir=tmp_path)
    notified=[]
    monkeypatch.setattr(service, '_notify', lambda *args: notified.append(args))
    service.mode='replay'
    service.record(dict(type='incident_start', notification=True, features=dict(n_exec=55,n_open_errors=547,n_open=8,n_tcp_connect=0)))
    event=service.events[0]
    assert '55 process executions' in event['explanation']['observations']
    assert 'not proof' in event['explanation']['limitation']
    assert not notified  # accelerated historical replay must not spam desktop alerts
    service.close()


def test_native_popup_does_not_depend_on_broken_system_notifications(tmp_path, monkeypatch):
    service=Service(data_dir=tmp_path)
    calls=[]
    service.alert_popup=lambda *args: calls.append(args) or True
    monkeypatch.setattr('desktop.service.desktop_notify',lambda *_: (_ for _ in ()).throw(AssertionError('Should not call daemon')))
    service._notify('Test alert','No threat detected')
    assert calls == [('Test alert','No threat detected')]
    assert service.notification_status['delivered']
    service.close()
