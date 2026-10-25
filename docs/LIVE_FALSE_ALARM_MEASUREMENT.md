# Live false-alarm measurement, 25 October 2026

What this is: one 57.5-minute live session on Ubuntu WSL with the installed model (profile-union SVM).
The machine was otherwise idle. Eight scripted, harmless routine tasks ran at fixed times (apt update, git,
a small C compile, a Python script plus virtualenv, grep/find searches, tar create/extract, five HTTPS header
requests, Python/file inspection). Nothing in this run was an attack.

What this is not: a sample of anyone's real workload, and not a general accuracy estimate. It shows how the
tool behaves on an otherwise quiet Ubuntu system with a few ordinary command-line tasks.

## Result

| Measure | Value |
|---|---|
| Complete 5-second windows | 691 |
| Flagged windows | 23 (3.3%) |
| Incident groups (2+ consecutive flagged windows) | 6 |
| Flagged windows caused by the routine tasks | 14 |
| Flagged windows caused by the measurement itself | 9 |
| Flagged windows with no identifiable cause | 0 |

The 9 measurement-caused windows were my own status checks at session start (2), Windows-to-WSL interop calls
made by the test driver (2), and the `powershell.exe` launch that opens the Windows alert window (5).
Every one of the 668 unflagged windows, including all idle gaps between tasks, stayed normal.

Incidents: start-up status check (artifact), apt update (classified as routine maintenance, no popup),
compile, Python virtualenv, search (`find`/`grep`), and network (`curl`). All four task incidents had
**low** severity.

## What it showed, and what was changed

1. **A real bug.** An earlier attempt ended after 21 minutes because `opensnoop` prints a row with no path when a
   program opens `""` (Python does this at start-up) and the parser treated it as event loss. Fixed; empty
   paths are valid and up to 25 unparseable rows per run are counted instead of aborting the session.
2. **Routine tasks look unusual to the model.** Short bursts from compilers, virtualenv creation, `find` and
   `curl` are flagged because the model only sees seven aggregate counts. Before the change below, four of
   these would have opened a Windows popup.
3. **Popup policy.** Popups now open only for medium and high severity. Low-severity incidents stay in the app
   (banner, live feed, history). A worse window inside an ongoing low incident escalates and opens a popup.
   Re-test: the same four routine tasks gave 0 popups; the demo burst gave a medium popup; the simulated
   credential access gave a high popup that lists `/etc/shadow`.

## Limits

- One session, one machine, scripted tasks. No Windows-side activity is observed.
- The severity rules are simple thresholds on already-flagged windows; they can hide a quiet attack as "low"
  (such an attack remains visible in the banner, the feed and the history).
- Process-name matching for routine maintenance can be spoofed by a local attacker.
