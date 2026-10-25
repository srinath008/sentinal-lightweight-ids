import json
from pathlib import Path
import numpy as np
import pandas as pd
import pytest
from feature_engineering.events import Window, parse_event, FEATURES
from feature_engineering.features import build_feature_table
from feature_engineering.replay import replay_session
from models.validated_training import split_sessions, calibrate, metrics
from inference.detector import IncidentGrouper, Detector


def test_shared_origin_empty_windows_and_tcp_only():
    empty = pd.DataFrame(columns=['timestamp', 'session_id'])
    tcp = pd.DataFrame([dict(timestamp=100., session_id='a', daddr='x', phase='baseline'),
                        dict(timestamp=115., session_id='a', daddr='y', phase='baseline')])
    result = build_feature_table(empty, empty, tcp)
    assert result.n_tcp_connect.tolist() == [1, 0, 0, 1]
    assert result.window_start.tolist() == [100, 105, 110, 115]
    execution = pd.DataFrame([dict(timestamp=110., session_id='a', pcomm='bash', phase='baseline')])
    result = build_feature_table(execution, empty, tcp)
    assert result.n_exec.tolist() == [0, 0, 1, 0]


def test_failed_open_multiword_names_and_numeric_path():
    row = parse_event('opensnoop', '100 Socket Thread -1 13 /tmp/12 34 file')
    assert row['fd'] == -1 and row['err'] == 13 and row['path'] == '/tmp/12 34 file'
    assert parse_event('tcpconnect', '100 Socket Thread 4 127.0.0.1 1.2.3.4 80')['comm'] == 'Socket Thread'
    assert parse_event('execsnoop', 'worker pool 100 1 0 /bin/demo x')['pcomm'] == 'worker pool'


def test_replay_matches_batch_and_counts_bad_rows(tmp_path):
    (tmp_path / 'execsnoop.csv').write_text('100.0,bash 1 0 0 bash\n110.0,ls 2 1 0 ls\n')
    (tmp_path / 'opensnoop.csv').write_text('100.5,PID COMM FD ERR PATH\n106.0,2 worker -1 13 /tmp/a\nbad\n')
    (tmp_path / 'tcpconnect.csv').write_text('111.0,2 Socket Thread 4 127.0.0.1 1.2.3.4 80\n')
    result = list(replay_session(tmp_path))
    assert len(result) == 3
    assert [r['n_exec'] for r, _ in result] == [1, 0, 1]
    assert [r['n_open_errors'] for r, _ in result] == [0, 1, 0]
    assert result[-1][1]['malformed'] == 1
    frames = []
    for source in ('execsnoop', 'opensnoop', 'tcpconnect'):
        records = []
        for line in (tmp_path / f'{source}.csv').read_text().splitlines():
            try:
                stamp, raw = line.split(',', 1)
                event = parse_event(source, raw)
                if event:
                    records.append(dict(event, timestamp=float(stamp), session_id=tmp_path.name, phase='unlabeled'))
            except ValueError:
                pass
        frames.append(pd.DataFrame(records))
    batch = build_feature_table(*frames)
    np.testing.assert_allclose(batch[FEATURES], pd.DataFrame([r for r, _ in result])[FEATURES])


def test_nonmonotonic_capture_rejected(tmp_path):
    for source in ('opensnoop', 'tcpconnect'):
        (tmp_path / f'{source}.csv').write_text('')
    (tmp_path / 'execsnoop.csv').write_text('110.0,bash 1 0 0 bash\n100.0,bash 1 0 0 bash\n')
    with pytest.raises(RuntimeError, match='Non-monotonic'):
        list(replay_session(tmp_path))


def test_split_rejects_overlap_and_missing_baseline():
    frame = pd.DataFrame(dict(session_id=['a', 'b', 'c', 'c'], phase=['baseline', 'baseline', 'baseline', 'attack_recon']))
    train, valid, test = split_sessions(frame, ['a'], ['b'], ['c'])
    assert set(train.session_id) == {'a'} and set(test.session_id) == {'c'}
    with pytest.raises(ValueError, match='disjoint'):
        split_sessions(frame, ['a'], ['b'], ['a'])
    with pytest.raises(ValueError, match='Missing'):
        split_sessions(frame, ['a'], ['b'], ['d'])


def test_calibration_ties_and_zero_fpr():
    scores = np.array([-9, -9, -8, -7, -6])
    for rate in (0, .1, .4):
        threshold = calibrate(scores, rate)
        assert (scores < threshold).mean() <= rate
    with pytest.raises(ValueError):
        calibrate([np.nan], .1)


def test_incidents_consecutive_end_and_cooldown():
    group = IncidentGrouper(consecutive=2, cooldown=60)
    row = dict(Window().row('live', 0, 100, 5), scores={}, anomaly=True)
    assert group.update(row) is None
    row['window_start'] = 105
    assert group.update(row)['notification'] is True
    assert group.update(row) is None
    row['anomaly'] = False
    assert group.update(row) is None
    assert group.update(row)['type'] == 'incident_end'
    row['anomaly'] = True
    assert group.update(row) is None
    assert group.update(row)['notification'] is False


def test_heldout_metrics_exclude_unlabeled():
    frame = pd.DataFrame(dict(phase=['baseline', 'baseline', 'attack_recon', 'unlabeled']))
    result = metrics(frame, [-2, 0, -3, -9], -1, 5)
    assert result['excluded_windows'] == 1
    assert result['recall'] == 1
    assert result['flagged_baseline_windows_per_hour'] == 360


def test_end_to_end_bundle(tmp_path):
    from argparse import Namespace
    from models.validated_training import train
    rows = []
    for sid in ('train', 'validation', 'test'):
        for index in range(60):
            window = Window()
            window.add('execsnoop', {'pcomm': 'bash'}, 'baseline')
            rows.append(window.row(sid, index, 100, 5))
    attack = Window()
    for _ in range(100):
        attack.add('tcpconnect', {'daddr': '127.0.0.1'}, 'attack_recon')
    rows.append(attack.row('test', 60, 100, 5))
    feature_path = tmp_path / 'features.parquet'
    pd.DataFrame(rows).to_parquet(feature_path)
    feature_path.with_suffix('.metadata.json').write_text(json.dumps(dict(schema_version=2, window_seconds=5,
        window_origin='first_valid_event_across_sources')))
    train(Namespace(features=feature_path, train=['train'], validation=['validation'], test=['test'],
                    target_fpr=.01, output=tmp_path / 'model'))
    detector = Detector(tmp_path / 'model/detector_bundle.joblib')
    assert detector.seconds == 5
    assert set(detector.score(rows[-1])['scores']) == {'isolation_forest', 'ocsvm'}


def test_incomplete_session_rejected(tmp_path):
    (tmp_path / 'manifest.json').write_text(json.dumps({'status': 'incomplete'}))
    with pytest.raises(ValueError, match='Incomplete'):
        list(replay_session(tmp_path))


def test_incident_metrics_reports_existing_incident():
    from models.incident_metrics import incident_metrics
    frame = pd.DataFrame(dict(session_id=['s'] * 4, window_index=[0, 1, 2, 3],
                             window_start=[0, 5, 10, 15],
                             phase=['baseline', 'baseline', 'attack_recon', 'attack_fileaccess']))
    result = incident_metrics(frame, np.array([-2., -2., -2., -2.]), -1, 5)
    assert result['baseline_notifications'] == 1
    assert result['scenarios'][0]['incident_active_at_phase_start'] is True


def test_streaming_collector_failure_cleans_processes(monkeypatch, tmp_path, capsys):
    import io
    from argparse import Namespace
    from inference import streaming
    class FakeDetector:
        seconds = 5
    class Process:
        pid = 999
        stdout = io.StringIO('')
        stderr = io.StringIO('')
        def poll(self):
            return None
        def wait(self, timeout=None):
            return 0
    killed = []
    for source in ('execsnoop', 'opensnoop', 'tcpconnect'):
        (tmp_path / source).touch()
    count = [0]
    def launch(*args, **kwargs):
        count[0] += 1
        if count[0] == 2:
            raise OSError('collector startup failed')
        return Process()
    monkeypatch.setattr(streaming.sys, 'platform', 'linux')
    monkeypatch.setattr(streaming, 'Detector', lambda path: FakeDetector())
    monkeypatch.setattr(streaming.subprocess, 'Popen', launch)
    monkeypatch.setattr(streaming.os, 'killpg', lambda pid, sig: killed.append(pid), raising=False)
    with pytest.raises(OSError, match='startup'):
        streaming.run(Namespace(bundle=tmp_path / 'model', tools_dir=tmp_path, duration=.1,
                                grace=.25, consecutive=2, cooldown=60))
    assert killed == [999]
    assert 'monitor_stopped' in capsys.readouterr().out
