"""Bounded, on-demand ClamAV scanning as the ordinary user; never delete files."""
from collections import deque
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time


def engine_status():
    binary = shutil.which('clamscan')
    database = Path('/var/lib/clamav')
    signatures = [p for p in database.glob('*') if p.suffix in ('.cvd', '.cld') and p.name.split('.')[0] in ('main', 'daily')]
    return dict(installed=bool(binary), ready=bool(binary and signatures),
                signature_updated=max((p.stat().st_mtime for p in signatures), default=None),
                note='On-demand scanning; not automatic file-access protection. Scan engine memory is additional to the behavioral model.')


class Scanner:
    def __init__(self, callback):
        self.callback = callback
        self.lock = threading.RLock()
        self.cancel = threading.Event()
        self.worker = None
        self.process = None
        self.summary_seen = False
        self.result = dict(status='idle', detections=[], detection_count=0, candidates=0, skipped=0, scanned=0)

    def snapshot(self):
        with self.lock:
            return dict(self.result, engine=engine_status())

    def start(self, target):
        if not isinstance(target, str) or not target.strip():
            raise ValueError('Enter a Linux file or folder path')
        path = Path(target).expanduser()
        if path.is_symlink() or not path.exists() or not (path.is_file() or path.is_dir()):
            raise ValueError('Choose an existing regular file or folder; symlinks are excluded')
        if not engine_status()['ready']:
            raise ValueError('ClamAV engine or official signatures are missing. Update signatures before scanning.')
        with self.lock:
            if self.worker and self.worker.is_alive():
                raise ValueError('A file scan is already running')
            self.result = dict(status='running', target=str(path.absolute()), detections=[], detection_count=0, candidates=0, skipped=0, scanned=0,
                               limit_reached=False, error=None, peak_memory_mib=0)
            self.cancel.clear()
            self.summary_seen = False
            self.worker = threading.Thread(target=self._run, args=(path.absolute(),), daemon=True)
            self.worker.start()

    def _run(self, target):
        try:
            files, skipped, visited = [], 0, 0
            def walk_error(_):
                nonlocal skipped
                skipped += 1
            entries = [(str(target.parent), [], [target.name])] if target.is_file() else os.walk(target, followlinks=False, onerror=walk_error)
            for directory, subdirs, names in entries:
                visited += 1
                original_subdirs = len(subdirs)
                subdirs[:] = [n for n in subdirs if not (Path(directory) / n).is_symlink()]
                skipped += original_subdirs - len(subdirs)
                if visited > 10000 or self.cancel.is_set():
                    self.result['limit_reached'] = True
                    break
                for name in names:
                    path = Path(directory) / name
                    try:
                        if path.is_symlink() or not path.is_file() or path.stat().st_size > 25 * 1024**2 or '\n' in str(path) or '\r' in str(path):
                            skipped += 1
                            continue
                    except OSError:
                        skipped += 1
                        continue
                    files.append(str(path))
                    if len(files) >= 2000:
                        self.result['limit_reached'] = True
                        break
                if len(files) >= 2000:
                    break
            self.result.update(candidates=len(files), skipped=skipped)
            if files and not self.cancel.is_set():
                with tempfile.TemporaryDirectory(prefix='sentinel-scan-') as folder:
                    manifest = Path(folder) / 'files.txt'
                    manifest.write_text('\n'.join(files) + '\n')
                    command = [shutil.which('clamscan'), '--stdout', '--file-list=' + str(manifest),
                               '--max-filesize=25M', '--max-scansize=100M', '--max-recursion=16',
                               '--alert-exceeds-max=yes', '--alert-encrypted=yes',
                               '--follow-dir-symlinks=0', '--follow-file-symlinks=0']
                    output = deque(maxlen=60)
                    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as process:
                        self.process = process
                        reader = threading.Thread(target=lambda: self._read(process, output), daemon=True)
                        reader.start()
                        deadline = time.monotonic() + 300
                        while process.poll() is None:
                            try:
                                for line in Path(f'/proc/{process.pid}/status').read_text().splitlines():
                                    if line.startswith('VmRSS:'):
                                        self.result['peak_memory_mib'] = max(self.result['peak_memory_mib'], round(int(line.split()[1]) / 1024, 1))
                            except OSError:
                                pass
                            if self.cancel.wait(.2) or time.monotonic() > deadline:
                                self.result['limit_reached'] = True
                                process.terminate()
                                try:
                                    process.wait(timeout=3)
                                except subprocess.TimeoutExpired:
                                    process.kill()
                                break
                        code = process.wait()
                        reader.join(timeout=3)
                    # clamscan exits 2 when any single file could not be read (for example "Access denied"),
                    # but it still scans the rest and prints a summary: that is a partial scan, not a failure.
                    if (code not in (0, 1, 2) or (code == 2 and not self.summary_seen)) and not self.cancel.is_set():
                        raise RuntimeError('ClamAV could not complete the scan: ' + '\n'.join(output)[-1500:])
            self.result['status'] = 'stopped' if self.cancel.is_set() else 'partial' if (self.result['limit_reached'] or self.result['skipped']) else 'completed'
        except Exception as exc:
            self.result.update(status='error', error=str(exc))
        finally:
            self.process = None
            self.callback(dict(type='file_scan_result', mode='file_scan', message=f"File scan {self.result['status']}: {self.result['detection_count']} detection(s)", scan=dict(self.result)))

    def _read(self, process, output):
        for raw in process.stdout:
            line = raw.strip()
            output.append(line[:2000])
            if line.endswith(' OK'):
                self.result['scanned'] += 1
            elif line.endswith(' FOUND'):
                self.result['scanned'] += 1
                self.result['detection_count'] = self.result.get('detection_count', 0) + 1
                if len(self.result['detections']) < 50:
                    path, _, signature = line[:-6].rpartition(': ')
                    self.result['detections'].append(dict(path=path, signature=signature,
                                                        kind='scan limitation' if signature.startswith(('Heuristics.Limits.', 'Heuristics.Encrypted.')) else 'heuristic alert' if signature.startswith('Heuristics.') else 'signature detection'))
            elif line.endswith(' ERROR') or line.endswith(': Access denied') or ": Can't open file" in line:
                self.result['skipped'] += 1
            elif 'SCAN SUMMARY' in line:
                self.summary_seen = True

    def stop(self):
        self.cancel.set()
        if self.worker:
            self.worker.join(timeout=6)
