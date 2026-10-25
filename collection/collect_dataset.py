"""Capture timestamped CO-RE logs on Linux; optional localhost simulations."""
import argparse
import csv
import json
import math
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import threading
import time

SOURCES = ('execsnoop', 'opensnoop', 'tcpconnect')


def run(args):
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise RuntimeError('Run on Linux with sudo for eBPF collection')
    import pwd
    if args.simulate and not shutil.which('nmap'):
        raise RuntimeError('nmap is required for localhost simulation')
    user = os.environ.get('SUDO_USER')
    if args.simulate and (not user or user == 'root'):
        raise RuntimeError('Invoke through sudo from a normal user for simulations')
    account = pwd.getpwnam(user) if user else None
    args.output.mkdir(parents=True, exist_ok=False)
    processes, threads, handles = [], [], []
    failures = []
    counts = {source: 0 for source in SOURCES}
    manifest = dict(start_epoch=time.time(), timestamp='userspace receipt time',
                    simulated=args.simulate, tools_dir=str(args.tools_dir),
                    kernel=os.uname().release, status='running')

    def copy(source, stream, output, timestamped):
        try:
            for line in stream:
                output.write(f'{time.time():.6f},' + line if timestamped else line)
                if timestamped:
                    counts[source] += 1
                else:
                    if 'lost' in line.lower() or 'drop' in line.lower():
                        failures.append(f'{source}: {line.strip()}')
        except Exception as error:
            failures.append(f'{source}: {error}')

    def health():
        if failures:
            raise RuntimeError('; '.join(failures))
        for source, process in processes:
            if process.poll() is not None:
                raise RuntimeError(f'{source} exited: {process.returncode}')
        if shutil.disk_usage(args.output).free < 1024**3:
            raise RuntimeError('Less than 1 GiB free; stopping capture')

    def phase(name, seconds, commands=None):
        start = time.time()
        end = time.monotonic() + seconds
        try:
            while time.monotonic() < end:
                health()
                if commands:
                    for command in commands:
                        remaining = end - time.monotonic()
                        if remaining <= 0:
                            break
                        proc = subprocess.Popen(['sudo', '-u', user, '--', *command],
                                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                                start_new_session=True)
                        try:
                            proc.wait(timeout=min(remaining, 10))
                        except subprocess.TimeoutExpired:
                            os.killpg(proc.pid, signal.SIGKILL)
                            proc.wait()
                        finally:
                            if proc.poll() is None:
                                os.killpg(proc.pid, signal.SIGKILL)
                                proc.wait()
                time.sleep(min(args.interval, max(0, end - time.monotonic())))
        finally:
            with (args.output / 'phase_log.csv').open('a', newline='') as handle:
                csv.writer(handle).writerow([name, start, time.time()])

    try:
        with (args.output / 'phase_log.csv').open('w', newline='') as handle:
            csv.writer(handle).writerow(['phase', 'start_epoch', 'end_epoch'])
        for source in SOURCES:
            binary = args.tools_dir / source
            if not binary.is_file():
                raise FileNotFoundError(binary)
            command = ['stdbuf', '-oL', '-eL', str(binary)]
            if source == 'execsnoop':
                command.append('--quote')
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True, bufsize=1, start_new_session=True)
            processes.append((source, process))
            for stream, suffix, timestamped in ((process.stdout, 'csv', True), (process.stderr, 'err', False)):
                handle = (args.output / f'{source}.{suffix}').open('w', buffering=65536)
                handles.append(handle)
                thread = threading.Thread(target=copy, args=(source, stream, handle, timestamped), daemon=True)
                thread.start()
                threads.append(thread)
        (args.output / 'manifest.json').write_text(json.dumps(manifest, indent=2))
        phase('baseline', args.baseline)
        if args.simulate:
            # Enumeration is bounded to common executable directories; no '/' crawl.
            phase('attack_recon', args.attack_seconds,
                  [['nmap', '-sT', '-Pn', '-p', '1-100', '127.0.0.1']])
            phase('attack_privesc', args.attack_seconds,
                  [['find', '/usr/bin', '/usr/sbin', '-maxdepth', '1', '-type', 'f', '-perm', '/6000'], ['id']])
            fixtures = args.output / 'simulation-fixtures'
            fixtures.mkdir()
            for index in range(100):
                fixture = fixtures / f'secret-demo-{index}.txt'
                fixture.write_text('Synthetic demo data; no credentials.\n')
                os.chmod(fixture, 0o644)
            os.chmod(args.output, 0o755)
            os.chmod(fixtures, 0o755)
            phase('attack_fileaccess', args.attack_seconds,
                  [['cat', str(path)] for path in sorted(fixtures.glob('*.txt'))])
        health()
        manifest['status'] = 'complete'
    except BaseException as error:
        manifest['status'], manifest['error'] = 'incomplete', str(error)
        raise
    finally:
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
            thread.join(timeout=3)
        for handle in handles:
            handle.close()
        if failures:
            manifest['status'] = 'incomplete'
        manifest.update(end_epoch=time.time(), line_counts=counts, failures=failures)
        (args.output / 'manifest.json').write_text(json.dumps(manifest, indent=2))
        if account:
            for path in [args.output, *args.output.rglob('*')]:
                os.chown(path, account.pw_uid, account.pw_gid)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tools-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='New session directory')
    parser.add_argument('--baseline', type=float, default=3600)
    parser.add_argument('--simulate', action='store_true')
    parser.add_argument('--attack-seconds', type=float, default=900)
    parser.add_argument('--interval', type=float, default=5)
    args = parser.parse_args()
    if any(not math.isfinite(value) or value <= 0 for value in (args.baseline, args.attack_seconds, args.interval)):
        parser.error('durations and interval must be positive')
    run(args)


if __name__ == '__main__':
    main()
