"""Local application state; the UI never runs with collector privileges."""
from collections import deque
import json
import html
from datetime import datetime, timezone
import os
from pathlib import Path
import platform
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
from contextlib import nullcontext

from inference.detector import Detector, IncidentGrouper
from desktop.alerts import explain, desktop_notify
from desktop.scanner import Scanner

ROOT = Path(__file__).resolve().parents[1]


class Service:
    def __init__(self, root=ROOT, data_dir=None, report_dir=None):
        self.root = Path(root)
        self.data_dir = Path(data_dir or Path(os.environ.get('XDG_STATE_HOME', Path.home() / '.local/state')) / 'sentinel')
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.db = self.data_dir / 'history.sqlite3'
        with sqlite3.connect(self.db) as db:
            db.execute('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, created REAL, payload TEXT)')
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.worker = None
        self.process = None
        self.windows = deque(maxlen=120)
        self.events = deque(maxlen=100)
        self.status, self.mode, self.error = 'idle', None, None
        self.total = self.flagged = self.incidents = 0
        self.detector = Detector(self.root / 'models/output/improved/detector_bundle.joblib')
        bundle = self.detector.bundle
        historical_metrics = bundle.get('evaluation_summary')
        if historical_metrics is None and bundle.get('primary_name') == 'ocsvm_log_g0.1_nu0.02':
            historical_metrics = dict(recall=246/248, baseline_false_positive_rate=9/352,
                                      f1=0.9781312127236581, true_positives=246,
                                      false_negatives=2, false_positives=9, true_negatives=343)
        self.model_info = dict(display_name=bundle.get('display_name', 'One-Class SVM'),
            family=bundle.get('family'),scope=bundle.get('evaluation_scope'),
            historical_metrics=historical_metrics,local_evaluation=bundle.get('local_evaluation'),
            experimental_host_adaptation=bool(bundle.get('adaptation_gates')))
        self.report_dir = Path(report_dir or Path.home() / 'Documents/Sentinel Reports')
        self.scanner = Scanner(self.record)
        self.notification_status = dict(delivered=False, detail='In-app alerts active. Use Test alert to check Linux desktop notifications.')
        self.sequence = 0
        self.alert_popup = None

    def checks(self):
        linux = sys.platform == 'linux'
        tools = Path('/opt/sentinel/collectors')
        return [
            dict(name='Current model', ok=True, detail=self.detector.bundle.get('primary_name', 'Calibrated model')),
            dict(name='Linux kernel', ok=linux, detail=platform.release() if linux else 'Replay available; live monitoring requires Linux'),
            dict(name='Kernel BTF', ok=linux and Path('/sys/kernel/btf/vmlinux').is_file(), detail='Required for CO-RE collectors'),
            dict(name='CO-RE collectors', ok=all(os.access(tools / x, os.X_OK) for x in ('execsnoop', 'opensnoop', 'tcpconnect')), detail=str(tools)),
            dict(name='Privilege helper', ok=linux and bool(shutil.which('pkexec')) and Path('/opt/sentinel/bin/sentinel-collector').is_file(), detail='Linux authorization is requested when monitoring starts'),
        ]

    def snapshot(self):
        with self.lock:
            return dict(status=self.status, mode=self.mode, error=self.error, total=self.total,
                        flagged=self.flagged, incidents=self.incidents, windows=list(self.windows),
                        events=list(self.events), checks=self.checks(), version='0.1.0',
                        model=self.detector.bundle.get('primary_name'), model_info=self.model_info,
                        window_seconds=self.detector.seconds)

    def protection_state(self):
        memory = None
        try:
            for line in Path('/proc/self/status').read_text().splitlines():
                if line.startswith('VmRSS:'):
                    memory = round(int(line.split()[1]) / 1024, 1)
        except OSError:
            pass
        return dict(scanner=self.scanner.snapshot(), notifications=self.notification_status, app_memory_mib=memory,
                    scope='Linux behavioral monitoring and on-demand ClamAV scanning. No automatic blocking or quarantine.')

    def record(self, event):
        with self.lock:
            self.sequence += 1
            event = dict(event, mode=event.get('mode', self.mode), event_id=self.sequence, recorded_at=time.time())
            if event['type'] == 'incident_start':
                event['explanation'] = explain(event)
            if event['type'] == 'window':
                self.total += 1
                self.flagged += int(event['anomaly'])
                self.windows.append(event)
            else:
                self.events.appendleft(event)
                self.incidents += int(event['type'] == 'incident_start')
                with sqlite3.connect(self.db) as db:
                    db.execute('INSERT INTO events(created,payload) VALUES (?,?)', (time.time(), json.dumps(event)))
                    db.execute('DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 1000)')
        # Every live incident alerts (incidents are already grouped, so this cannot spam);
        # the model's 60 s cooldown only decides the quiet 'notification' flag.
        if event['type'] == 'incident_start' and event['mode'] == 'live':
            threading.Thread(target=self._notify, args=('Unusual Linux activity', '; '.join(event['explanation']['observations'])), daemon=True).start()
        if event['type'] == 'file_scan_result' and event.get('scan', {}).get('detections'):
            threading.Thread(target=self._notify, args=('ClamAV scan needs review', event['message']), daemon=True).start()

    def _notify(self, title, message):
        if self.alert_popup:
            try:
                if self.alert_popup(title, message):
                    self.notification_status = dict(delivered=True, detail='Native Sentinel popup requested; in-app alert is also available.')
                    return
            except Exception:
                pass  # In-app alerts remain available even without desktop support.
        self.notification_status = desktop_notify(title, message)

    def test_alert(self):
        self.record(dict(type='test_alert', mode='demo', message='Test alert only. No threat was detected.'))
        self._notify('Sentinel test alert', 'This is a notification test, not a threat detection.')
        return self.notification_status

    def _windows_path(self, path):
        """Windows-visible form of a Linux path when running under WSL, else None."""
        distro = os.environ.get('WSL_DISTRO_NAME')
        if not distro or 'microsoft' not in platform.release().lower():
            return None
        return '\\\\wsl.localhost\\' + distro + str(path).replace('/', '\\')

    def open_reports_folder(self):
        self.report_dir.mkdir(parents=True, exist_ok=True)
        windows = self._windows_path(self.report_dir)
        if windows and shutil.which('explorer.exe'):
            subprocess.Popen(['explorer.exe', windows], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return dict(opened=True, folder=str(self.report_dir), windows_folder=windows)
        opener = shutil.which('xdg-open')
        if opener:
            subprocess.Popen([opener, str(self.report_dir)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return dict(opened=True, folder=str(self.report_dir), windows_folder=None)
        return dict(opened=False, folder=str(self.report_dir), windows_folder=None)

    def _report_html(self, report):
        esc = html.escape
        session, history = report['session'], report['history']
        def when(stamp):
            return datetime.fromtimestamp(stamp, timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC') if stamp else ''
        rows = []
        for e in history:
            x = e.get('explanation') or {}
            ctx = x.get('context') or {}
            detail = [e.get('message') or '']
            detail += x.get('observations', [])
            if ctx.get('exec_commands'):
                detail.append('Commands started: ' + ', '.join(f"{c['name']} x{c['count']}" for c in ctx['exec_commands']))
            if ctx.get('processes'):
                detail.append('Processes: ' + ', '.join(f"{p['name']} (PID {p['pid']}, {p['observed_events']} {p['source']})" for p in ctx['processes']))
            if ctx.get('sample_paths'):
                detail.append('Paths: ' + '; '.join(ctx['sample_paths']))
            if ctx.get('sample_destinations'):
                detail.append('Destinations: ' + '; '.join(ctx['sample_destinations']))
            rows.append('<tr><td>' + esc(when(e.get('created'))) + '</td><td>' + esc(str(e.get('type'))) + '</td><td>' + esc(str(e.get('mode') or '')) + '</td><td>' + '<br>'.join(esc(str(d)) for d in detail if d) + '</td></tr>')
        summary = [('Status', session['status']), ('Mode', session['mode'] or 'none'), ('Windows analyzed', session['total']),
                   ('Flagged windows', session['flagged']), ('Incident groups', session['incidents']), ('Model', session['model'])]
        return ('<!doctype html><meta charset="utf-8"><title>Sentinel report</title>'
                '<style>body{font:14px system-ui,Arial;max-width:1100px;margin:30px auto;padding:0 16px;color:#1c2420}'
                'table{border-collapse:collapse;width:100%}td,th{border:1px solid #c8d2cb;padding:6px 9px;text-align:left;vertical-align:top;font-size:13px}'
                'th{background:#eef3ef}.note{background:#fff4e5;border:1px solid #e0b36f;padding:10px;border-radius:6px}</style>'
                '<h1>Sentinel activity report</h1><p>Exported ' + esc(report['exported_at']) + '</p>'
                '<p class="note">' + esc(report['note']) + '</p><h2>Session summary</h2><table>'
                + ''.join(f'<tr><th>{esc(k)}</th><td>{esc(str(v))}</td></tr>' for k, v in summary)
                + '</table><h2>Incident and health history (' + str(len(history)) + ' events)</h2><table><tr><th>Time</th><th>Event</th><th>Mode</th><th>Detail</th></tr>'
                + ''.join(rows) + '</table><details><summary>Raw data (JSON)</summary><pre>'
                + esc(json.dumps(report, indent=2, allow_nan=False)) + '</pre></details>')

    def export_report(self):
        report = dict(application='Sentinel', exported_at=datetime.now(timezone.utc).isoformat(),
                      session=self.snapshot(), protection=self.protection_state(), history=self.history(),
                      note='Anomalies are not proof of malware. Replay is historical. Window detail is limited to the most recent 120 windows; history includes up to 1000 retained events. ClamAV is a separate on-demand engine.')
        self.report_dir.mkdir(parents=True, exist_ok=True)
        base = 'sentinel-' + datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')
        content = json.dumps(report, indent=2, allow_nan=False)
        paths = []
        for suffix, text in (('.json', content), ('.html', self._report_html(report))):
            path = self.report_dir / (base + suffix)
            with path.open('x', encoding='utf-8') as output:
                output.write(text)
            paths.append(str(path))
        return dict(saved_files=paths, windows_files=[self._windows_path(p) for p in paths] if self._windows_path(paths[0]) else [],
                    folder=str(self.report_dir), message='Report saved locally as JSON and readable HTML.')

    def history(self):
        with sqlite3.connect(self.db) as db:
            return [dict(id=row[0], created=row[1], **json.loads(row[2])) for row in db.execute('SELECT id,created,payload FROM events ORDER BY id DESC LIMIT 1000')]

    def start(self, mode, speed=0.08):
        if mode not in ('replay', 'live'):
            raise ValueError('Choose replay or live monitoring')
        with self.lock:
            if self.worker and self.worker.is_alive():
                raise ValueError('Stop the current session first')
            if mode == 'live' and not all(c['ok'] for c in self.checks()):
                raise ValueError('Live prerequisites are incomplete. Open System checks for details.')
            self.mode, self.status, self.error = mode, 'starting', None
            self.total = self.flagged = self.incidents = 0
            self.windows.clear()
            self.events.clear()
            self.stop_event.clear()
            self.worker = threading.Thread(target=self._work, args=(mode, speed), daemon=True)
            self.worker.start()

    def _work(self, mode, speed):
        try:
            if mode == 'replay':
                self._replay(speed)
            else:
                external_agent = 'microsoft' in platform.release().lower()
                self._live(external_agent=external_agent)
            with self.lock:
                self.status = 'stopped' if self.stop_event.is_set() else 'completed'
        except Exception as exc:
            with self.lock:
                self.status, self.error = 'error', str(exc)
            self.record(dict(type='error', message=str(exc)))
        finally:
            with self.lock:
                self.process = None

    def _replay(self, speed):
        self.status = 'running'
        previous = None
        group = IncidentGrouper()
        with (self.root / 'desktop/replay.jsonl').open(encoding='utf-8') as stream:
            for line in stream:
                if self.stop_event.is_set():
                    break
                row = json.loads(line)
                key = (row['session_id'], row['window_index'])
                if previous and (key[0] != previous[0] or key[1] != previous[1] + 1):
                    group = IncidentGrouper()
                    self.record(dict(type='replay_boundary', message='New recording segment; incident grouping reset'))
                previous = key
                scored = self.detector.score(row)
                self.record(dict(type='window', **scored))
                incident = group.update(scored)
                if incident:
                    self.record(incident)
                if self.stop_event.wait(speed):
                    break

    def _live(self, external_agent=False):
        if self.stop_event.is_set():
            return
        # pkexec authorizes its parent (this GUI process). No password handling.
        from desktop.authorization import authorization_terminal
        context = authorization_terminal(self.stop_event, os.getpid()) if external_agent else nullcontext(True)
        with context as ready:
            if not ready:
                return
            command = ['pkexec']
            if external_agent:
                command.append('--disable-internal-agent')
            command.append('/opt/sentinel/bin/sentinel-collector')
            with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, bufsize=1) as process:
                with self.lock:
                    self.process = process
                errors = deque(maxlen=20)
                reader = threading.Thread(target=lambda: errors.extend(process.stderr), daemon=True)
                reader.start()
                started = False
                for line in process.stdout:
                    event = json.loads(line)
                    if event['type'] == 'monitor_started':
                        started = True
                        self.status = 'running'
                    self.record(event)
                code = process.wait()
                reader.join(timeout=1)
                if not self.stop_event.is_set() and (code != 0 or not started):
                    raise RuntimeError('Live monitoring could not start or was interrupted. ' + ''.join(errors)[-2000:])

    def stop(self):
        self.stop_event.set()
        with self.lock:
            process = self.process
        # pkexec replaces itself with the root helper. A request file is used
        # because an ordinary UI cannot signal a root collector directly.
        if process and process.poll() is None:
            request = Path('/run/sentinel') / str(os.getuid()) / 'stop'
            try:
                request.touch()
            except OSError:
                pass
            # Cancel pending pkexec authentication too; root collectors use
            # the request file when the ordinary user cannot signal them.
            try:
                process.terminate()
            except (PermissionError, ProcessLookupError):
                pass
        if self.worker:
            self.worker.join(timeout=5)
        return self.snapshot()

    def close(self):
        self.stop()
        self.scanner.stop()
