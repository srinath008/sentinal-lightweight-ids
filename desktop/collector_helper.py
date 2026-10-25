"""Fixed root-owned entry point installed by the Sentinel installer."""
import fcntl
import os
from pathlib import Path
import pwd
import signal
import subprocess
import sys
import time


def main():
    if os.geteuid() != 0:
        raise SystemExit('Collector helper requires Linux authorization')
    uid = int(os.environ.get('PKEXEC_UID', '-1'))
    if uid < 1:
        raise SystemExit('Launch the helper from the Sentinel application')
    user = pwd.getpwuid(uid)
    root = Path('/run/sentinel')
    root.mkdir(mode=0o755, exist_ok=True)
    directory = root / str(uid)
    if not directory.exists():
        directory.mkdir(mode=0o700)
        os.chown(directory, uid, user.pw_gid)
    if directory.is_symlink() or directory.stat().st_uid != uid:
        raise SystemExit('Unsafe runtime directory')
    request = directory / 'stop'
    # Lock is outside the user-writable directory to prevent lock replacement.
    with (root / f'{uid}.lock').open('w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit('A collector session is already running')
        # A rejected second launch must not erase the active session's stop request.
        request.unlink(missing_ok=True)
        command = ['/opt/sentinel/.venv/bin/python', '-I', '-c',
                   "import sys; sys.path.insert(0, '/opt/sentinel'); from inference.streaming import main; main()",
                   '--bundle', '/opt/sentinel/models/output/improved/detector_bundle.joblib',
                   '--tools-dir', '/opt/sentinel/collectors', '--duration', '14400']
        env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C.UTF-8'}
        stopping = False
        def stop(*_):
            nonlocal stopping
            stopping = True
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        parent = os.getppid()
        with subprocess.Popen(command, cwd='/opt/sentinel', env=env) as process:
            while process.poll() is None:
                if stopping or request.exists() or os.getppid() != parent:
                    process.terminate()
                    try:
                        process.wait(timeout=12)
                    except subprocess.TimeoutExpired:
                        process.kill()
                    break
                time.sleep(.2)
            request.unlink(missing_ok=True)
            return process.wait()


if __name__ == '__main__':
    sys.exit(main())
