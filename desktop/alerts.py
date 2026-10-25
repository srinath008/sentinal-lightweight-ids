"""Evidence summaries describe observations, not malware causality."""
import math
import shutil
import subprocess


def explain(event):
    f = event.get('features', {})
    opens = f.get('n_open_raw', round(math.expm1(f.get('n_open', 0))))
    observations = [f"{int(f.get('n_exec', 0))} process executions",
                    f"{int(opens):,} file opens",
                    f"{int(f.get('n_open_errors', 0)):,} file-open errors",
                    f"{int(f.get('n_tcp_connect', 0))} TCP connections (including local)"]
    return dict(summary='The model flagged a combination of activity outside its learned normal pattern.',
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
    from gi.repository import Gtk, GLib
    if not isinstance(window.native, Gtk.Window):
        return False
    def show():
        dialog = Gtk.MessageDialog(transient_for=window.native, modal=False,
                                   message_type=Gtk.MessageType.WARNING, buttons=Gtk.ButtonsType.CLOSE,
                                   text=title[:150])
        dialog.set_title('Sentinel alert')
        dialog.format_secondary_text(message[:1200])
        dialog.connect('response', lambda widget, _: widget.destroy())
        dialog.show_all()
        return False
    GLib.idle_add(show)
    return True
