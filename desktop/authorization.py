"""WSL authorization using polkit's own terminal agent; no password handling."""
from contextlib import contextmanager
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import tempfile
import time


@contextmanager
def authorization_terminal(stop_event, subject_pid):
    with tempfile.TemporaryDirectory(prefix='sentinel-auth-') as folder:
        ready=Path(folder)/'ready'
        binary=shutil.which('xterm')
        if not binary or not shutil.which('pkttyagent'):
            raise RuntimeError('WSL live monitoring requires xterm and pkttyagent for administrator authorization.')
        process=subprocess.Popen([binary,'-T','Sentinel - Ubuntu authorization','-e',sys.executable,'-I',
                                  str(Path(__file__).resolve()),str(subject_pid),str(ready)],
                                 stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            deadline=time.monotonic()+10
            while not ready.exists():
                if stop_event.wait(.1):
                    yield False
                    return
                if process.poll() is not None or time.monotonic()>deadline:
                    raise RuntimeError('The Linux authorization terminal could not register. Check WSLg display support.')
            yield True
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def terminal_main():
    pid=int(sys.argv[1])
    ready=Path(sys.argv[2])
    print('Sentinel requests administrator authorization for Linux monitoring.\n'
          'Enter your Ubuntu password only when polkit prompts below.\n'
          'The Sentinel app does not read or store this password.\n',flush=True)
    read_fd,write_fd=os.pipe()
    # Include start time so a recycled PID cannot identify another process.
    stat=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()
    identity=f'{pid},{stat[19]}'  # field 22: process start time
    # WSL has no login session: polkit 124 skips fallback-only agents when
    # session lookup fails. Register this process-scoped agent directly.
    process=subprocess.Popen(['pkttyagent','--process',identity,'--notify-fd',str(write_fd)],pass_fds=(write_fd,))
    os.close(write_fd)
    try:
        if not select.select([read_fd],[],[],8)[0] or process.poll() is not None:
            raise RuntimeError('polkit agent registration failed')
        os.read(read_fd,1)  # EOF signals that registration completed.
        ready.write_text('registered')
        while process.poll() is None:
            try:
                os.kill(pid,0)
            except ProcessLookupError:
                break
            time.sleep(.2)
    finally:
        os.close(read_fd)
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=3)


if __name__=='__main__':
    terminal_main()
