import json
from pathlib import Path
import threading
import time
import urllib.error
import urllib.request

import pytest

from desktop.app import make_server
from desktop.service import Service, ROOT


@pytest.fixture
def service(tmp_path):
    instance = Service(data_dir=tmp_path)
    yield instance
    instance.stop()


def test_actual_model_replay_and_persistent_history(service):
    service.start('replay', 0)
    service.worker.join(timeout=20)
    assert service.status == 'completed', service.error
    assert service.total == 600
    assert service.flagged == 255  # 246 true positive + 9 false positive
    assert len(service.windows) == 120
    assert any(e['type'] == 'incident_start' for e in service.history())
    assert all(e['mode'] == 'replay' for e in service.history())
    fresh = Service(data_dir=service.data_dir)
    assert fresh.history() == service.history()


def test_stop_and_refuse_overlapping_sessions(service):
    service.start('replay', 5)
    with pytest.raises(ValueError, match='Stop'):
        service.start('replay')
    service.stop()
    assert service.status == 'stopped'
    assert service.total < 600


def test_history_is_bounded(service):
    for i in range(1010):
        service.record(dict(type='error', message=str(i)))
    assert len(service.history()) == 1000
    assert service.history()[-1]['message'] == '10'


def test_live_rejects_missing_prerequisites(service, monkeypatch):
    monkeypatch.setattr(service, 'checks', lambda: [dict(ok=False)])
    with pytest.raises(ValueError, match='prerequisites'):
        service.start('live')


@pytest.mark.parametrize('external_agent', [True, False])
def test_live_uses_one_authorization_agent(service, monkeypatch, external_agent):
    import io
    import os
    from contextlib import contextmanager
    commands = []
    subjects = []

    class Process:
        stdout = io.StringIO('{"type":"monitor_started"}\n')
        stderr = io.StringIO('')

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def wait(self):
            return 0

        def poll(self):
            return 0

    def launch(command, **kwargs):
        commands.append(command)
        return Process()

    monkeypatch.setattr('desktop.service.subprocess.Popen', launch)
    @contextmanager
    def agent(stop_event, subject_pid):
        subjects.append(subject_pid)
        assert not commands  # register before pkexec starts
        yield True
    monkeypatch.setattr('desktop.authorization.authorization_terminal', agent)
    service._live(external_agent=external_agent)
    if external_agent:
        assert subjects == [os.getpid()]
        assert commands[0] == ['pkexec', '--disable-internal-agent', '/opt/sentinel/bin/sentinel-collector']
    else:
        assert subjects == []
        assert commands[0] == ['pkexec', '/opt/sentinel/bin/sentinel-collector']
    assert service.status == 'running'


@pytest.mark.skipif(__import__('os').name != 'posix', reason='Linux process identity uses procfs')
def test_wsl_agent_is_not_fallback_only(tmp_path, monkeypatch):
    import os
    from desktop import authorization
    commands = []
    polls = iter([None, 0, 0])

    class Agent:
        def poll(self):
            return next(polls)

    def launch(command, **kwargs):
        commands.append(command)
        return Agent()

    ready = tmp_path / 'ready'
    monkeypatch.setattr(authorization.sys, 'argv', ['authorization.py', str(os.getpid()), str(ready)])
    monkeypatch.setattr(authorization.subprocess, 'Popen', launch)
    monkeypatch.setattr(authorization.select, 'select', lambda *args: ([1], [], []))
    monkeypatch.setattr(authorization.os, 'read', lambda *args: b'')
    authorization.terminal_main()
    assert ready.read_text() == 'registered'
    assert '--fallback' not in commands[0]
    identity = commands[0][commands[0].index('--process') + 1]
    assert identity.startswith(f'{os.getpid()},')
    assert int(identity.split(',')[1]) > 0


def test_loopback_auth_origin_and_no_file_traversal(service):
    server, token = make_server(service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f'http://127.0.0.1:{server.server_port}'
    def request(path, headers=None, payload=None):
        req = urllib.request.Request(url + path, headers=headers or {}, data=payload)
        try:
            with urllib.request.urlopen(req, timeout=3) as r:
                return r.status, r.read(), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read(), dict(e.headers)
    try:
        assert server.server_address[0] == '127.0.0.1'
        assert request('/api/state')[0] == 403
        auth = {'X-Sentinel-Token': token}
        assert request('/api/state', auth)[0] == 200
        assert request('/api/state', dict(auth, Origin='https://example.com'))[0] == 403
        assert request('/api/state', dict(auth, Host='attacker.example'))[0] == 403
        assert request('/api/start', auth, b'{"mode":"arbitrary"}')[0] == 400
        assert request('/api/start', auth, b'[]')[0] == 400
        assert request('/../../docs/PROJECT_HANDOFF.md')[0] == 404
        assert b'Content-Security' not in request('/')[1]
        assert "frame-ancestors 'none'" in request('/')[2]['Content-Security-Policy']
    finally:
        server.shutdown()
        server.server_close()


def test_dashboard_reuses_tcp_connection_and_rejects_unread_bodies(service):
    import http.client
    server, token = make_server(service)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=3)
    try:
        ports = []
        for path in ('/api/state', '/api/protection', '/api/state'):
            connection.request('GET', path, headers={'X-Sentinel-Token': token})
            response = connection.getresponse()
            assert response.status == 200
            assert response.version == 11
            response.read()
            assert connection.sock is not None
            ports.append(connection.sock.getsockname()[1])
        assert len(set(ports)) == 1
        connection.request('POST', '/api/start', body=b'{}', headers={
            'X-Sentinel-Token': token, 'Content-Length': '2048'})
        try:
            response = connection.getresponse()
        except ConnectionError:
            # Winsock may reset a socket closed with unread request bytes.
            pass
        else:
            assert response.status == 400
            response.read()
            assert response.will_close
            assert connection.sock is None
        assert service.status == 'idle'  # rejected request never starts work
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
