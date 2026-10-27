# Sentinel 0.1.0 — research preview

Sentinel is an installable Linux behavioral detection application. It uses the
existing calibrated One-Class SVM. It is not a file antivirus and does not
quarantine or block anything. WSL monitoring covers Linux, not Windows.

## Install on Ubuntu / WSL 2

The first installer targets x86_64 Ubuntu/Debian. Internet access and sudo are
needed to install dependencies. It is a source/runtime preview archive, not a
self-contained AppImage or a Windows installer. Installation has not yet been
verified on a clean Linux machine. Exact runtime dependencies match the supplied
model; do not silently change scikit-learn versions.

Download the archive and SHA256SUMS.txt into the same directory. In Ubuntu:

```bash
sha256sum -c SHA256SUMS.txt
tar -xzf sentinel-0.1.0-linux-x86_64.tar.gz
cd sentinel-0.1.0
bash release_tools/install.sh
sentinel
```

The installer places root-owned files in `/opt/sentinel`, adds an applications
menu entry and creates the `sentinel` launcher. Use `sentinel --browser` if your
Ubuntu environment has no native GUI. With WSL, the printed local address can
also be opened in a Windows browser. Keep the launching terminal open in browser
mode; Ctrl+C stops the application.

Choose **Recorded replay → Start replay** first. The included 600 historical
feature windows are rescored with the existing model, with no raw process names,
paths, file contents or destination addresses included. Fast replay is accelerated
playback; it does not monitor current activity. Gaps between recorded segments
reset incident grouping. Use Export report to save local results.

## Live monitoring prerequisites

Open System checks. Live mode requires Linux, `/sys/kernel/btf/vmlinux`, pkexec,
and the exact native CO-RE `execsnoop`, `opensnoop`, `tcpconnect` tools. BCC Python
scripts or similarly named tools with different text schemas are not equivalent.
The original project used tools built from `iovisor/bcc/libbpf-tools`.

If you already have matching trusted collector binaries:

```bash
sudo install -d -m 755 /opt/sentinel/collectors
sudo install -m 755 "$HOME/bcc/libbpf-tools/execsnoop" /opt/sentinel/collectors/
sudo install -m 755 "$HOME/bcc/libbpf-tools/opensnoop" /opt/sentinel/collectors/
sudo install -m 755 "$HOME/bcc/libbpf-tools/tcpconnect" /opt/sentinel/collectors/
```

For a fresh build, follow the official upstream instructions at
https://github.com/iovisor/bcc/tree/master/libbpf-tools and record the exact source
revision used. Build as your ordinary user; install only reviewed binaries. The
application does not download and execute arbitrary collector builds.

Start Live Linux monitoring. Linux will request administrator authorization for
the fixed root-owned helper. The UI and local server remain unprivileged. A
graphical polkit authorization agent is needed; a CLI-only WSL environment may
need an Ubuntu desktop/WSLg authorization agent or a VM before this flow works.
Each live session is limited to one hour. Stop session requests graceful cleanup.

Passing file-existence checks does not certify schema compatibility or zero event
loss. Verify a short live session against normal process/file/network activity,
collector error reporting, Stop session, and application-close cleanup before
demonstrating live detection. Live performance remains unverified until then.

## Privacy and limitations

Inference runs locally. The application makes no outbound telemetry requests.
Up to 1,000 incident and health records are retained in
`~/.local/state/sentinel/history.sqlite3` (or XDG_STATE_HOME). Reports may include
collector diagnostics; review them before sharing. Closing live mode stops the
collector helper; closing a browser tab alone does not close the background app.

The reserved historical test recorded 99.19% simulated-window recall, 2.56%
normal-window false alarms and F1 0.978. These are results from two previously
examined recordings, not independent new-device validation. The application
does not certify that a device is free of malware.

## Uninstall

Close the application and run:

```bash
bash /opt/sentinel/release_tools/uninstall.sh
```

The installer directory is moved aside for recovery. Your local history is kept.

## UI credits

Layout adapted from Watermelon UI's Landing Page 01 and Gridline Dashboard,
reimplemented as dependency-free HTML/CSS for the local desktop runtime.
https://ui.watermelon.sh/template/landing-01
https://ui.watermelon.sh/dashboard/gridline-dashboard
See desktop/WATERMELON-LICENSE.txt for the upstream MIT notice.
