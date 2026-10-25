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


def test_every_live_incident_alerts_even_during_model_cooldown(tmp_path, monkeypatch):
    service = Service(data_dir=tmp_path)
    notified = []
    monkeypatch.setattr(service, '_notify', lambda *args: notified.append(args))
    service.mode = 'live'
    features = dict(n_exec=55, n_open_errors=547, n_open=8, n_tcp_connect=0)
    service.record(dict(type='incident_start', notification=False, features=features))
    import time
    time.sleep(.2)
    assert len(notified) == 1
    service.close()


def test_evidence_ranks_actionable_processes_and_lists_commands():
    live = EvidenceWindow()
    for _ in range(50):
        live.add('opensnoop', dict(pid=333, comm='init', fd=3, err=0, path='/proc/x'))
    for _ in range(3):
        live.add('opensnoop', dict(pid=900, comm='find', fd=3, err=0, path='/etc/passwd'))
    for pid in range(4):
        live.add('execsnoop', dict(pid=1000 + pid, pcomm='curl', ppid=1, ret=0, args='curl x'))
    evidence = live.row('live', 0, 0, 5)['evidence']
    assert evidence['processes'][0]['name'] != 'init'
    assert evidence['exec_commands'][0] == dict(name='curl', count=4)


def test_html_report_is_readable_and_escapes_evidence(tmp_path, monkeypatch):
    from pathlib import Path
    service = Service(data_dir=tmp_path / 'state', report_dir=tmp_path / 'reports')
    service.mode = 'replay'
    service.record(dict(type='incident_start', notification=True, features=dict(n_exec=1, n_open_errors=0, n_open=1, n_tcp_connect=0),
                        evidence=dict(exec_commands=[dict(name='<b>x</b>', count=2)], processes=[], sample_paths=[], sample_destinations=[])))
    result = service.export_report()
    page = Path(result['saved_files'][1]).read_text()
    assert '<table>' in page and 'Incident and health history' in page
    assert '&lt;b&gt;x&lt;/b&gt;' in page and '<b>x</b>' not in page
    assert result['folder'] == str(tmp_path / 'reports')
    service.close()


def test_windows_path_is_derived_only_under_wsl(tmp_path, monkeypatch):
    service = Service(data_dir=tmp_path / 'state', report_dir=tmp_path / 'r')
    monkeypatch.setenv('WSL_DISTRO_NAME', 'Ubuntu')
    monkeypatch.setattr('platform.release', lambda: '6.6-microsoft-standard-WSL2')
    expected = '\\\\wsl.localhost\\Ubuntu\\home\\u\\Documents\\x.json'
    assert service._windows_path('/home/u/Documents/x.json') == expected
    monkeypatch.setattr('platform.release', lambda: '6.8-generic')
    assert service._windows_path('/home/u/x') is None
    service.close()


def test_sensitive_paths_are_recorded_without_reading_content():
    live = EvidenceWindow()
    live.add('opensnoop', dict(pid=5, comm='cat', fd=3, err=0, path='/etc/shadow'))
    live.add('opensnoop', dict(pid=5, comm='cat', fd=3, err=0, path='/home/u/.ssh/id_rsa'))
    live.add('opensnoop', dict(pid=5, comm='cat', fd=3, err=0, path='/etc/passwd'))
    assert live.row('live', 0, 0, 5)['evidence']['sensitive_paths'] == ['/etc/shadow', '/home/u/.ssh/id_rsa']


def test_severity_rules():
    from desktop.alerts import severity
    assert severity({}, dict(sensitive_paths=['/etc/shadow']))[0] == 'high'
    assert severity(dict(n_tcp_connect=900), {})[0] == 'high'
    assert severity(dict(n_exec=300), {})[0] == 'medium'
    assert severity(dict(n_exec=2, n_open=3), {})[0] == 'low'


def test_expected_maintenance_requires_only_routine_programs():
    from desktop.alerts import expected_maintenance
    apt = dict(processes=[dict(name='apt-get'), dict(name='gpgv'), dict(name='init')],
               exec_commands=[dict(name='dpkg'), dict(name='sh')], sensitive_paths=[])
    assert expected_maintenance(apt)
    assert expected_maintenance(dict(apt, processes=apt['processes'] + [dict(name='python')]))
    assert not expected_maintenance(dict(apt, processes=apt['processes'] + [dict(name='python3')]))
    assert not expected_maintenance(dict(apt, sensitive_paths=['/etc/shadow']))
    assert not expected_maintenance(dict(apt, exec_commands=[dict(name='nmap')]))
    assert not expected_maintenance(dict(apt, processes=[dict(name='apt-get'), dict(name='curl')]))
    assert not expected_maintenance(dict(processes=[dict(name='sh')], exec_commands=[]))  # no recognised program
    assert not expected_maintenance({})


def test_expected_live_incident_is_recorded_but_does_not_alert(tmp_path, monkeypatch):
    import time
    service = Service(data_dir=tmp_path)
    notified = []
    monkeypatch.setattr(service, '_notify', lambda *args: notified.append(args))
    service.mode = 'live'
    features = dict(n_exec=119, n_open_errors=282, n_open=8, n_tcp_connect=1)
    routine = dict(processes=[dict(name='apt-get', pid=1, source='opensnoop', observed_events=9)],
                   exec_commands=[dict(name='dpkg', count=3)], sensitive_paths=[])
    service.record(dict(type='incident_start', notification=True, features=features, evidence=routine))
    service.record(dict(type='incident_start', notification=True, features=features,
                        evidence=dict(routine, sensitive_paths=['/etc/shadow'])))
    time.sleep(.2)
    first, second = service.events[1], service.events[0]
    assert first['expected'] and not second.get('expected')
    assert second['explanation']['severity'] == 'high'
    assert len(notified) == 1 and 'HIGH' in notified[0][0] and '/etc/shadow' in notified[0][1]
    service.close()


def test_windows_alert_is_not_attempted_outside_wsl(monkeypatch):
    from desktop import alerts
    monkeypatch.setattr('platform.release', lambda: '6.8-generic')
    assert alerts.windows_alert('t', 'm')['delivered'] is False


def test_windows_alert_keeps_output_piped_and_caps_open_windows(monkeypatch):
    import subprocess
    from desktop import alerts
    monkeypatch.setattr('platform.release', lambda: '6.6-microsoft-standard-WSL2')
    monkeypatch.setattr(alerts.shutil, 'which', lambda _: '/bin/true')
    monkeypatch.setattr(alerts.shutil.os.path, 'exists', lambda _: True)
    launched = []

    class Fake:
        def poll(self): return None            # window still open
        def communicate(self): return ('', '')
    def popen(command, **kwargs):
        launched.append(kwargs)
        return Fake()
    monkeypatch.setattr(alerts.subprocess, 'Popen', popen)
    alerts._alert_processes.clear()
    results = [alerts.windows_alert('t', 'm') for _ in range(alerts.MAX_OPEN_ALERTS + 3)]
    assert all(r['delivered'] for r in results)
    assert len(launched) == alerts.MAX_OPEN_ALERTS
    assert launched[0]['stdout'] == subprocess.PIPE and launched[0]['stderr'] == subprocess.PIPE
    alerts._alert_processes.clear()
