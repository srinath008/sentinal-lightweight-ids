# Sentinel demo runbook (final review, 28 October)

Everything below was run on the installed Ubuntu WSL app on 25 October unless it says otherwise.
Use recorded replay as the main demonstration. Treat live mode as an optional extra.

## Before the review (the evening before)

1. Close every Sentinel window, then confirm nothing is left running:
   `wsl -d Ubuntu -- bash -c "ps -eo pid,cmd | grep -E 'collectors/|sentinel-collector' | grep -v grep"`
   (no output is correct).
2. Start the app: `wsl -d Ubuntu -- /usr/local/bin/sentinel` (or run `sentinel` inside Ubuntu).
   If no window appears, use `sentinel --browser` and open the printed address.
3. Open **System checks**: all five checks must show a tick.
4. Run one recorded replay (below) and one **Test alert** so any first-run delay is out of the way.
5. Rehearse the live segment once, including typing your Ubuntu password in the authorization window.
   The password prompt could not be tested automatically.
6. Optional: reset the incident history so the demo starts empty (delete
   `~/.local/state/sentinel/history.sqlite3` in Ubuntu while the app is closed).

## Five-minute demo

1. **About the model.** Say: profile-union SVM, experimental preview, trained on two native sessions;
   99.19% simulated-window recall and 1.99% normal-window false alarms are historical numbers,
   not general malware accuracy.
2. **Overview, Recorded replay, Fast.** About 50 seconds. Expect 600 windows, 253 flagged, 7 incident groups.
   The Live window feed fills as windows arrive; flagged rows show recorded labels.
3. **Test alert.** An always-on-top "Sentinel alert" window opens on the Windows desktop. Click Dismiss.
4. **ClamAV scan.** Path `/home/srinath/Sentinel-Test-Files`. Expect 3 files scanned, 1 harmless EICAR
   test-signature detection, 0 skipped. Never execute the fixture.
5. **Export report.** A message appears bottom-right with the Windows path; **Open reports folder**
   opens it in Explorer. The HTML report has a summary table and an evidence table.

## Optional live segment (about 2 minutes)

1. Choose **Live Linux monitoring**, press Start, enter the Ubuntu password in the authorization window.
2. Wait for the first windows to appear in the feed (about 10 seconds). Idle activity should not alert.
3. In a second Ubuntu terminal, run the harmless burst:
   `bash /mnt/e/"Amrita Academics"/"SEM3 AIM"/OS/project/tests/manual/demo_burst.sh`
   Expect a medium-severity Windows alert (it stays open until you press Dismiss; at most five stay open) about 10 to 15 seconds after it starts.
4. Then the credential-access simulation:
   `bash /mnt/e/"Amrita Academics"/"SEM3 AIM"/OS/project/tests/manual/demo_credential_sim.sh`
   Expect a high-severity alert listing `/etc/shadow` and `/etc/sudoers`. The kernel refuses the reads;
   the attempt is the signal and no contents are read.
5. Press **Stop session**.

## What to say about limits

- It monitors Linux inside WSL only, not Windows applications.
- It flags unusual bursts of process, file and network activity; it does not identify malware.
- Alerts need two consecutive flagged 5-second windows, so expect 10 to 15 seconds of delay.
- Routine apt/dpkg maintenance is recorded in history but raises no popup. The check matches process names.
- Normal activity such as builds can still raise alerts; the model was trained on two sessions of one laptop.
- ClamAV is a separate on-demand scanner and uses about 1 GB of memory while scanning.

## If something goes wrong

| Symptom | Fix |
|---|---|
| No app window | Run `sentinel --browser` and open the printed address |
| Live start fails | Show recorded replay instead; check System checks |
| No popup on live incident | The in-app red banner and the feed still show it; continue |
| Password window missing | Check the Windows taskbar for "Sentinel - Ubuntu authorization" |
| Leftover collectors | `wsl -d Ubuntu -u root -- pkill -f /opt/sentinel/collectors/` |
