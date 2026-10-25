"""Evidence summaries describe observations, not malware causality."""
import base64
import math
import platform
import shutil
import subprocess


def severity(features, context):
    """Rule-of-thumb triage of an already-flagged window; it does not change what the model flags."""
    tcp, execs = features.get('n_tcp_connect', 0), features.get('n_exec', 0)
    errors = features.get('n_open_errors', 0)
    opens = features.get('n_open_raw', round(math.expm1(features.get('n_open', 0))))
    if context.get('sensitive_paths'):
        return 'high', 'Credential or privilege files were opened: ' + ', '.join(context['sensitive_paths'][:3])
    if tcp >= 200:
        return 'high', f'{int(tcp)} TCP connections in one window (possible network scan).'
    if execs >= 100 or opens >= 50000 or errors >= 1000:
        return 'medium', 'Large burst of process starts or file activity.'
    return 'low', 'Mild departure from the learned normal pattern.'


# Comm names are truncated to 15 characters by the kernel. A name can be spoofed by a local attacker,
# so a match only downgrades the popup; the incident is still recorded and shown in history.
MAINTENANCE_PROGRAMS = frozenset({
    'apt', 'apt-get', 'apt-helper', 'apt-config', 'apt-key', 'apt-check', 'dpkg', 'dpkg-query', 'dpkg-deb',
    'dpkg-preconfigu', 'dpkg-split', 'gpgv', 'gpg', 'unattended-upgr', 'update-notifier', 'apport',
    'ldconfig', 'man-db', 'mandb', 'lsb_release', 'update-motd-upd', 'cnf-update-db', 'snapd',
    'systemd-tmpfile', 'ubuntu-advantage', 'ua', 'esm_cache', 'gpg-connect-age', 'gpg-connect-agent', 'gpgconf',
    'gpg-agent', 'dirmngr', 'dpkg-trigger', 'update-alternati', 'apt-extracttempl', 'dpkg-maintscrip'})
MAINTENANCE_HELPERS = frozenset({
    'sh', 'bash', 'dash', 'run-parts', 'sleep', 'cat', 'grep', 'sed', 'date', 'stat', 'readlink',
    'dirname', 'basename', 'tr', 'wc', 'sort', 'cut', 'mktemp', 'rm', 'mv', 'cp', 'ln', 'mkdir', 'chmod',
    'which', 'uname', 'id', 'env', 'locale', 'find', 'xargs', 'tee', 'ls', 'test', 'true', 'false'})
INFRASTRUCTURE = frozenset({'init', 'systemd', 'systemd-journal', 'systemd-journald', 'systemd-udevd', 'snapd',
                            '(udev-worker)', 'systemd-udevd'})


def expected_maintenance(evidence):
    """True only when every named process is routine package maintenance and no credential path was touched."""
    if not evidence or evidence.get('sensitive_paths'):
        return False
    processes = {p['name'] for p in evidence.get('processes', [])}
    commands = {c['name'] for c in evidence.get('exec_commands', [])}
    if not processes and not commands:
        return False
    if not (processes | commands) & MAINTENANCE_PROGRAMS:
        return False  # at least one recognised maintenance program must be present
    # 'python' is Sentinel's own virtualenv interpreter (UI and collector); scripts run as python3.
    if processes - MAINTENANCE_PROGRAMS - MAINTENANCE_HELPERS - INFRASTRUCTURE - {'python'}:
        return False
    return not (commands - MAINTENANCE_PROGRAMS - MAINTENANCE_HELPERS)


def explain(event):
    f = event.get('features', {})
    opens = f.get('n_open_raw', round(math.expm1(f.get('n_open', 0))))
    observations = [f"{int(f.get('n_exec', 0))} process executions",
                    f"{int(opens):,} file opens",
                    f"{int(f.get('n_open_errors', 0)):,} file-open errors",
                    f"{int(f.get('n_tcp_connect', 0))} TCP connections (including local)"]
    level, reason = severity(f, event.get('evidence', {}))
    return dict(severity=level, severity_reason=reason, summary='The model flagged a combination of activity outside its learned normal pattern.',
                observations=observations, context=event.get('evidence', {}),
                limitation='These are observations in the flagged window, not proof that a listed process caused malware. Historical replay has no process/path attribution.')


def desktop_notify(title, message):
    binary = shutil.which('notify-send')
    if not binary:
        return dict(delivered=False, detail='Linux notifications unavailable; in-app alerts remain active.')
    try:
        result = subprocess.run([binary, '--app-name=Sentinel', '--expire-time=10000', '--', title, message],
                                capture_output=True, text=True, timeout=5)
        return dict(delivered=result.returncode == 0,
                    detail='Sent to Linux notification service.' if result.returncode == 0 else result.stderr.strip()[:300])
    except (OSError, subprocess.TimeoutExpired) as exc:
        return dict(delivered=False, detail=str(exc)[:300])


def native_popup(window, title, message):
    """Nonblocking GTK popup fallback when WSL has no notification daemon."""
    import gi
    gi.require_version('Gtk', '3.0')
    from gi.repository import Gtk, GLib, Gdk
    if not isinstance(window.native, Gtk.Window):
        return False
    def show():
        dialog = Gtk.MessageDialog(transient_for=window.native, modal=False,
                                   message_type=Gtk.MessageType.WARNING, buttons=Gtk.ButtonsType.CLOSE,
                                   text=title[:150])
        dialog.set_title('Sentinel alert')
        dialog.format_secondary_text(message[:1200])
        dialog.connect('response', lambda widget, _: widget.destroy())
        dialog.set_keep_above(True)  # a non-modal dialog must not hide behind the dashboard
        dialog.show_all()
        dialog.present()
        try:
            Gdk.beep()
        except Exception:
            pass
        return False
    GLib.idle_add(show)
    return True


_WINDOWS_ALERT = r"""
# The process starts with -WindowStyle Hidden, and that flag also hides the first window shown;
# the form is therefore shown explicitly with SW_SHOW below.
Add-Type -Name Native -Namespace Sentinel -MemberDefinition '[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$title = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__TITLE__'))
$text = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__TEXT__'))
[System.Media.SystemSounds]::Exclamation.Play()
$f = New-Object Windows.Forms.Form
$f.Text = 'Sentinel alert'; $f.TopMost = $true; $f.StartPosition = 'CenterScreen'
$f.Size = New-Object Drawing.Size(560, 330); $f.FormBorderStyle = 'FixedDialog'
$f.MaximizeBox = $false; $f.MinimizeBox = $false; $f.ShowInTaskbar = $true
$f.BackColor = [Drawing.Color]::FromArgb(48, 35, 24); $f.ForeColor = [Drawing.Color]::FromArgb(255, 212, 168)
$h = New-Object Windows.Forms.Label; $h.Text = $title; $h.Font = New-Object Drawing.Font('Segoe UI', 13, [Drawing.FontStyle]::Bold)
$h.Location = New-Object Drawing.Point(18, 14); $h.Size = New-Object Drawing.Size(510, 30)
$b = New-Object Windows.Forms.Label; $b.Text = $text; $b.Font = New-Object Drawing.Font('Segoe UI', 10)
$b.Location = New-Object Drawing.Point(18, 52); $b.Size = New-Object Drawing.Size(510, 190)
$o = New-Object Windows.Forms.Button; $o.Text = 'Dismiss'; $o.Location = New-Object Drawing.Point(430, 252)
$o.Size = New-Object Drawing.Size(100, 32); $o.ForeColor = [Drawing.Color]::Black; $o.BackColor = [Drawing.Color]::FromArgb(255, 186, 112)
$o.Add_Click({ $f.Close() })
$f.Controls.AddRange(@($h, $b, $o)); $f.AcceptButton = $o
$f.Add_Shown({ [void][Sentinel.Native]::ShowWindow($f.Handle, 5); $f.Activate(); $f.BringToFront() })
[void]$f.ShowDialog()
"""


def windows_alert(title, message):
    """Always-on-top Windows window via WSL interop; independent of Windows toast settings."""
    if 'microsoft' not in platform.release().lower():
        return dict(delivered=False, detail='Not running under WSL.')
    binary = shutil.which('powershell.exe') or '/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
    if not binary or not shutil.os.path.exists(binary):
        return dict(delivered=False, detail='Windows PowerShell is unavailable from WSL.')
    enc = lambda text: base64.b64encode(text[:1500].encode('utf-8')).decode()
    script = _WINDOWS_ALERT.replace('__TITLE__', enc(title)).replace('__TEXT__', enc(message))
    command = base64.b64encode(script.encode('utf-16-le')).decode()
    try:
        subprocess.Popen([binary, '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-EncodedCommand', command],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return dict(delivered=True, detail='Windows alert window requested.')
    except OSError as exc:
        return dict(delivered=False, detail=str(exc)[:300])
