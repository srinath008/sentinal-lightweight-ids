# Local Ubuntu installation — 2026-10-16

Sentinel 0.1.0 is installed in this PC's Ubuntu WSL 2 distribution
(Ubuntu 24.04.3 LTS, kernel 6.6.87.2-microsoft-standard-WSL2).

- Application: `/opt/sentinel`, owned by root, not writable by ordinary users.
- Launcher: `/usr/local/bin/sentinel`.
- Applications-menu entry: `/usr/share/applications/sentinel.desktop`.
- Current model SHA-256:
  `88167caf3a5250a99810bfb66604defa2425f9fc19e51b175ec22c4ba662b95a`.
- Desktop dependencies, GTK/WebKit and pkexec installed using apt.
- Isolated Python environment installed with the release's exact model runtime.

Installation used the checksummed release archive and performed the installer's
user and system steps separately through WSL. The interactive sudo-based
installer itself was not run end-to-end.

Verified from the permanent installation as the ordinary Ubuntu user: model
loads with its expected hash, all 600 replay windows complete, 255 are flagged,
and root ownership/permissions are correct. The installed launcher starts the
native desktop's WebKit rendering processes and its local interface responds
with HTTP 200. Native-window visual inspection is still pending.

## Open

From Ubuntu:

```bash
sentinel
```

From Windows PowerShell:

```powershell
wsl -d Ubuntu -- sentinel
```

Browser fallback: `sentinel --browser`. Use the printed local address and keep
the terminal open until you are done.

## UI fixes applied — 2026-10-16

The installed desktop now explicitly configures GTK minimize/maximize/close
controls and the application-local dark theme. Dropdowns suppress the light
native WebKit appearance and use readable dark backgrounds and light text.
Small text, focus indicators, status colors and narrow-window control layout
were improved. Missing live prerequisites lead to System checks; the brand
link returns to Overview. Native report downloads are enabled.

Verification: five application checks pass; real GTK widget checks confirm
the configured decoration layout and dark theme. Browser checks cover the
dropdown colors, mode switching, setup navigation and desktop/narrow layouts.
The fixes are applied to this local WSL installation and project source; the
public 0.1.0 download archive has not been republished with these UI changes.
Backups of the previous local interface are in `/opt/sentinel/ui-backup-*`.

## Live monitoring status (unchanged)

Linux kernel, BTF and the installed privilege helper pass prerequisite checks.
The CO-RE `execsnoop`, `opensnoop` and `tcpconnect` binaries are still absent
from `/opt/sentinel/collectors`; live monitoring is unavailable. No monitoring
or automatic startup was enabled. WSL detection observes Linux activity only.

Use Recorded replay for now. Collector setup and live verification remain a
separate next step; see APP_INSTALL.md for prerequisites and limitations.
