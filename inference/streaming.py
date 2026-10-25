"""Linux-only live CO-RE monitoring with bounded ingestion and health events."""
import argparse
import json
import math
import os
from pathlib import Path
import queue
import signal
import subprocess
import sys
import threading
import time
from feature_engineering.events import SOURCES, Window, parse_event, window_index
from inference.detector import Detector, IncidentGrouper
from inference.evidence import EvidenceWindow


def emit(event):
    print(json.dumps(event), flush=True)


def run(args):
    if sys.platform != 'linux':
        raise RuntimeError('Live collectors require Linux; use replay on Windows')
    detector = Detector(args.bundle)
    grouper = IncidentGrouper(args.consecutive, args.cooldown)
    pending = queue.Queue(maxsize=100000)
    failure = threading.Event()
    stopping = threading.Event()
    ingestion_lock = threading.Lock()
    processes, threads = [], []
    origin = time.time()
    monotonic_origin = time.monotonic()
    deadline = time.monotonic() + args.duration if args.duration else float('inf')
    windows, current = {}, 0
    window_origin = None
    stats = dict(malformed=0, late=0, stderr_lines=0, events=0)
    # Permit the privileged desktop helper to request a graceful shutdown.
    previous_term = None
    if threading.current_thread() is threading.main_thread():
        previous_term = signal.signal(signal.SIGTERM, lambda *_: stopping.set())

    def read_stdout(source, process):
        for raw in process.stdout:
            try:
                event = parse_event(source, raw)
                if event is not None:
                    with ingestion_lock:
                        stamp = origin + time.monotonic() - monotonic_origin
                        pending.put_nowait((stamp, source, event))
            except ValueError:
                stats['malformed'] += 1
                failure.set()
            except queue.Full:
                failure.set()
                return

    def read_stderr(source, process):
        for raw in process.stderr:
            stats['stderr_lines'] += 1
            emit(dict(type='collector_stderr', source=source, message=raw.rstrip()[:1000]))
            if 'lost' in raw.lower() or 'drop' in raw.lower():
                failure.set()

    try:
        for source in SOURCES:
            binary = args.tools_dir / source
            if not binary.is_file():
                raise FileNotFoundError(binary)
            # New process session permits cleanup of every launched collector.
            # Quoting escapes newlines in exec arguments, preserving one event
            # per line even for ordinary multiline Python/shell commands.
            command = ['stdbuf', '-oL', '-eL', str(binary)]
            if source == 'execsnoop':
                command.append('--quote')
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True, bufsize=1, start_new_session=True)
            processes.append((source, process))
            for reader in (read_stdout, read_stderr):
                thread = threading.Thread(target=reader, args=(source, process), daemon=True)
                thread.start()
                threads.append(thread)
        emit(dict(type='monitor_started', window_seconds=detector.seconds,
                  consecutive=args.consecutive, cooldown=args.cooldown))
        while not stopping.is_set() and time.monotonic() < deadline:
            if failure.is_set():
                raise RuntimeError('Event loss, incompatible collector output or queue overflow: monitoring results are incomplete')
            for source, process in processes:
                if process.poll() is not None:
                    raise RuntimeError(f'{source} exited with {process.returncode}')
            try:
                stamp, source, event = pending.get(timeout=.1)
                if origin + time.monotonic() - monotonic_origin - stamp > 2 * detector.seconds:
                    raise RuntimeError('Ingestion backlog exceeds two windows; live results are delayed')
                if window_origin is None:
                    window_origin = stamp
                idx = window_index(stamp, window_origin, detector.seconds)
                if idx < current:
                    stats['late'] += 1
                    raise RuntimeError('Late event arrived after its window was scored')
                windows.setdefault(idx, EvidenceWindow()).add(source, event)
                stats['events'] += 1
            except queue.Empty:
                pass
            # Drain backlog before finalizing, with a short inter-thread grace.
            if window_origin is None:
                continue
            now_index = window_index(origin + time.monotonic() - monotonic_origin - args.grace, window_origin, detector.seconds)
            while pending.empty() and current < now_index:
                row = windows.pop(current, EvidenceWindow()).row('live', current, window_origin, detector.seconds)
                scored = detector.score(row)
                incident = grouper.update(scored)
                emit(dict(type='window', **scored))
                if incident:
                    incident['evidence'] = row['evidence']
                    emit(incident)
                current += 1
    except KeyboardInterrupt:
        pass
    finally:
        stopping.set()
        for _, process in processes:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
        for _, process in processes:
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        for thread in threads:
            thread.join(timeout=1)
        emit(dict(type='monitor_stopped', complete_windows=current,
                  partial_windows_discarded=len(windows), **stats))
        if previous_term is not None:
            signal.signal(signal.SIGTERM, previous_term)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--tools-dir', type=Path, required=True)
    parser.add_argument('--duration', type=float, default=0)
    parser.add_argument('--grace', type=float, default=.25)
    parser.add_argument('--consecutive', type=int, default=2)
    parser.add_argument('--cooldown', type=float, default=60)
    args = parser.parse_args()
    if not all(math.isfinite(value) for value in (args.duration, args.grace)) or args.duration < 0 or args.grace < 0:
        parser.error('duration and grace must be nonnegative')
    run(args)


if __name__ == '__main__':
    main()
