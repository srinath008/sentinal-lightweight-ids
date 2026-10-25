import io
import json
import zipfile
from feature_engineering.lidds_scenario import inspect_recording, parameters


def recording(events, onset=None):
    buffer = io.BytesIO()
    metadata = dict(exploit=onset is not None, image='test-only', recording_time=20,
                    time={'exploit': [] if onset is None else [{'absolute':onset}]})
    with zipfile.ZipFile(buffer, 'w') as archive:
        archive.writestr('run.json', json.dumps(metadata))
        archive.writestr('run.sc', '\n'.join(events))
    return buffer.getvalue()


def test_udp_connect_is_not_a_tcp_feature():
    events = ['1000000000 0 1 sh 1 socket > domain=2(AF_INET) type=2050 proto=0',
              '1000000001 0 1 sh 1 socket < fd=3(<4>)',
              '1000000002 0 1 sh 1 connect > fd=3(<4>)',
              '1000000003 0 1 sh 1 connect < res=0 tuple=127.0.0.1:8->127.0.0.11:53',
              '11000000000 0 1 sh 1 select >']
    rows, report = inspect_recording(recording(events), 'run', 'training')
    assert report['stats']['udp_connect_exits'] == 1
    assert sum(row['n_tcp_connect'] for row in rows) == 0
    assert len(rows) == 2


def test_tcp_and_failed_open_count_once_and_keep_path_spaces():
    events = ['1000000000 0 1 sh 1 socket > domain=2(AF_INET) type=1 proto=6',
              '1000000001 0 1 sh 1 socket < fd=3(<4>)',
              '1000000002 0 1 sh 1 connect > fd=3(<4>)',
              '1000000003 0 1 sh 1 connect < res=0 tuple=127.0.0.1:8->1.2.3.4:80',
              '1000000004 0 1 sh 1 open >',
              '1000000005 0 1 sh 1 open < fd=-2(ENOENT) name=/tmp/my file flags=0 mode=0',
              '11000000000 0 1 sh 1 select >']
    rows, report = inspect_recording(recording(events), 'run', 'training')
    assert rows[0]['n_tcp_connect'] == rows[0]['n_unique_daddr'] == 1
    assert rows[0]['n_open_raw'] == rows[0]['n_open_errors'] == 1
    assert parameters('name=/tmp/my file flags=0')['name'] == '/tmp/my file'
    assert not report['stats'].get('unresolved_feature_events', 0)


def test_unobserved_socket_protocol_is_reported_not_assumed_tcp():
    rows, report = inspect_recording(recording([
        '1000000000 0 1 sh 1 connect > fd=3(<4>)',
        '1000000001 0 1 sh 1 connect < res=0 tuple=127.0.0.1:8->1.2.3.4:80',
        '11000000000 0 1 sh 1 select >']), 'run', 'test')
    assert report['stats']['connect_unknown_protocol'] == 1
    assert rows[0]['n_tcp_connect'] == 0


def test_attack_transition_is_omitted_not_labelled_as_entire_recording():
    rows, report = inspect_recording(recording([
        '1000000000 0 1 sh 1 select >',
        '21000000000 0 1 sh 1 select >'], onset=8.), 'run', 'test')
    assert [row['phase'] for row in rows] == ['baseline', 'attack_exposure', 'attack_exposure']
    assert report['stats']['omitted_transition_windows'] == 1
