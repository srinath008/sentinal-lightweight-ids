# Sentinel protection tools — 2026-10-16

The installed local prototype now combines the unchanged behavioral SVM with
a separate, real on-demand ClamAV antivirus scanner. An accurate description
is **ClamAV-powered on-demand antivirus prototype with Linux behavioral alerts**.
Do not attribute file-virus recognition to the SVM or claim commercial-grade
protection, automatic blocking, automatic quarantine, or full Windows monitoring.

## Reports

Export report writes JSON and HTML directly into
`/home/srinath/Documents/Sentinel Reports`. It no longer relies on WebKit Blob
downloads. The interface displays the saved paths. The report contains current
session totals, at most 120 recent windows, up to 1,000 retained incident/health
events, scanner results and notification status. It is not a full raw-event log.

Your completed 600-window replay was preserved before the upgrade as
`completed-replay-before-upgrade-20261016.json` in that folder.

Windows Explorer can access this folder at:
`\\wsl.localhost\Ubuntu\home\srinath\Documents\Sentinel Reports`.

## Alerts and explanations

Consecutive flagged live windows produce a persistent in-app alert and a
rate-limited native GTK popup. The GTK popup takes priority because WSL's
notification daemon failed in testing. Without a native window, a best-effort
Linux desktop notification is attempted.
Browser-only mode always has the in-app alert, but may lack a desktop popup.
**Test alert** is explicitly labelled as a test and does not imply a threat.
Accelerated replay does not send desktop notifications.

An incident shows process-execution, file-open, error and TCP counts. New live
windows additionally retain bounded top-process observations and sample file
paths/destinations. These are activity observed alongside a model flag, not
proof of which process caused malware. The historical replay lacks attribution.
Context collection leaves the model's numeric feature inputs unchanged.

## File scanning

Enter a Linux file or folder path and choose **Scan with ClamAV**. Official
signatures are installed and freshclam is configured by the Ubuntu package.
Scan work runs as your ordinary user; files are never executed, removed or
automatically quarantined. Review signature names and matched paths.

The scan is bounded to 2,000 selected regular files, 25 MiB per file, a 100 MiB
container scan limit, recursion limit 16 and 5 minutes of engine runtime.
Symlinks and inaccessible/oversized files are skipped. Encrypted contents or
engine limits generate review findings. Partial/stopped/error scans are not a
clean verdict. Displayed memory includes main-process RSS and a separately
sampled scan-process peak; WebKit child processes are additional.

Test folder: `/home/srinath/Sentinel-Test-Files`. It contains clean text and the
harmless official EICAR test file. The real scanner detected `Eicar-Test-Signature`
and left the file intact. No malware was executed. See
PROTECTION_VERIFICATION.json for actual results and saved report paths.

The test scan used about **1,000 MiB peak scanner RSS**. The engine unloads after
the on-demand scan. This is not evidence that the entire application is
ultra-lightweight; benchmarking on representative devices remains necessary.

## Live prerequisites and verification

CO-RE collectors were built from official BCC v0.35.0, commit
`c31a1ca305f787ba53e001ead45ebf65233a32cf`, and installed root-owned into
`/opt/sentinel/collectors`. A bounded normal-activity check scored two complete
windows from 2,550 events with no malformed/late rows or stderr messages.
It included process context. See LIVE_SMOKE_VERIFICATION.json. This is a
collector smoke check, not a threat-detection accuracy benchmark.

The standard polkit terminal authorization agent is used on WSL because its
graphical agent cannot identify a login session. Starting live mode opens a
small authorization terminal for the human's Ubuntu password. The application
does not read/store that password. Agent registration is checked before pkexec
starts; full human password approval still requires the user's test. No broader
passwordless policy was added. Do not run the main desktop as root.

The first human live-mode test exposed a duplicate-agent error: pkexec tried to
register its internal agent after Sentinel had registered the terminal agent.
The WSL launch now uses `pkexec --disable-internal-agent` with that already
registered agent; other Linux launches retain the default agent behavior.
Twelve focused desktop/protection tests pass, including both launch variants.
Human password approval must still be retested after this correction.

Follow-up: disabling the internal agent exposed `No authentication agent found`.
The actual cause was the terminal agent's `--fallback` option: polkit 124 skips
fallback selection when no login session can be resolved (as on this WSL setup).
The terminal agent now registers directly for pkexec's parent process, using
PID plus process start time. No system policy or password requirement changed.
A real unprivileged Ubuntu check reached pending authorization without either
agent error, and cancellation cleaned up the worker and agent. Password-approved
collector startup still requires the human's test.

## WSL storage recovery

The C: drive filled during setup and Ubuntu returned filesystem I/O errors.
With the user's approval, Ubuntu was backed up and moved using WSL's supported
move operation to `E:\WSL\Ubuntu`. Backup:
`E:\WSL\Backups\Ubuntu-before-sentinel-move-20261016-verified.vhdx`.
Ubuntu was then verified readable and writable. C: regained about 7.6 GB.

## Sources and scope

- Official ClamAV scanning documentation: https://docs.clamav.net/manual/Usage/Scanning.html
- Official signature updates: https://docs.clamav.net/manual/Usage/SignatureManagement.html
- Harmless EICAR test-file documentation: https://www.eicar.org/download-anti-malware-testfile/

These changes are in project source and the local Ubuntu installation. The
public download page's original 0.1.0 archive has not yet been republished with
these changes. The existing behavioral model and raw datasets were preserved.
