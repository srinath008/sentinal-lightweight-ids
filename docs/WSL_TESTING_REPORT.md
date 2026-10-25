# Sentinel WSL verification — 2026-10-17

## Outcome

Live collection, file scanning, report export and the previously human-tested
password/alert flow function. The current behavioral SVM remains unsuitable for
reliable default alerts on this WSL environment. Its high historical scores do
not transfer to the observed normal workloads. No model or cutoff was promoted.

## Controlled collector checks

A harmless ordinary-user workload launched 20 `printf` processes, read one clean
file 100 times, attempted to open a deliberately absent file 100 times, and made
100 connections to a temporary loopback listener. Files were temporary and
removed by the workload's normal cleanup; no malware was executed.

The initial test exposed an actual ingestion bug: multiline command arguments
were printed as multiple execsnoop rows. Monitoring correctly rejected the
malformed stream, but legitimate commands could therefore interrupt protection.
Live execsnoop now uses `--quote`, whose native implementation escapes argument
newlines. The shared seven numeric feature inputs and model remain unchanged.
This correction is installed in `/opt/sentinel` as well as project source.

The final isolated probe captured exactly 20 `printf` executions, 101 clean-file
opens (creation plus 100 reads), 100 expected missing-file errors, and 100 TCP
connections to the test listener's unique port. It scored four complete windows
with zero malformed/late events and zero collector stderr lines. One incomplete
end window was deliberately discarded. See WSL_COLLECTOR_PROBE_AFTER.json.
WSL workload/procfs PIDs should not be assumed interchangeable with kernel
collector PIDs; unique test paths and destination port identify the file/TCP
markers. The earlier probe is retained in WSL_COLLECTOR_PROBE_BEFORE.json.

## Normal workload and app noise

| Sequential phase | Complete five-second windows | Flagged |
|---|---:|---:|
| App closed, requested idle | 6 | 4 |
| Native app open, requested idle | 6 | 6 |
| Native app open, harmless controlled workload | 4 | 4 |
| Native app open, later requested idle | 6 | 6 |

All four phases finished without collector errors, malformed rows or late
events. See WSL_LIVE_DIAGNOSTICS.json. Each app-open idle phase recorded 76 TCP
events; the first phase attributes them to WebKitNetworkPr. The closed-app
phase had no TCP events. This supports that Sentinel's own local interface
contributes normal connections to its input counts. It is not external traffic.

Ubuntu unattended upgrades ran during the open-app phases. The later period's
top file-open sources included `dpkg`, `mandb` and `systemd`. Those are observed
benign maintenance workloads, not evidence that Sentinel caused the entire
increase in activity. These short sequential runs do not isolate CPU/file
overhead, establish a population false-positive rate, or measure attack accuracy.
No automatic-update settings were changed and no update process was stopped.

## Cutoff calibration experiment

The model was frozen. Two exploratory lower cutoffs were computed: one from
the first 25 windows of the earlier 51-window report (assumed normal, without
ground-truth labels), and one from the six new app-open normal windows. Later
WSL windows and all 600 historical reserved replay windows were evaluated after
each cutoff was fixed. The historical data have previously been examined;
this is regression evidence, not a fresh independent validation dataset.

| Cutoff | Historical attack windows detected | Historical baseline false positives | Later WSL normal flags |
|---|---:|---:|---:|
| Installed | 246/248 (99.19%) | 9/352 (2.56%) | 6/6 |
| Earlier WSL calibration | 78/248 (31.45%) | 0/352 | 1/6 |
| Short new app-open calibration | 78/248 (31.45%) | 0/352 | 6/6 |

Both lower cutoffs missed every retained privilege-escalation and file-access
attack window. Reducing alerts this way sacrifices detection; neither cutoff
was installed. See WSL_CALIBRATION_RESULTS.json for thresholds, feature ranges,
per-phase recall and limitations. The unchanged model SHA-256 is
`88167caf3a5250a99810bfb66604defa2425f9fc19e51b175ec22c4ba662b95a`.

## File scanning, export and regression checks

ClamAV scanned the three existing test files as the ordinary user: one harmless
EICAR signature detection, no skipped files, and no other detections. All file
hashes remained unchanged. JSON and readable HTML report exports were parsed
and checked. Scan peak RSS was 999.8 MiB, additional to the application and
renderer. See WSL_FILE_SCAN_CHECK.json. This tests the EICAR integration, not
general malware detection efficacy or an ultra-lightweight memory claim.

The existing automated suite passed 38 tests, with one Linux-only procfs test
skipped on Windows. After the collector correction, 24 relevant parsing,
desktop and protection checks passed, with the same skipped test. Actual Ubuntu
collector checks above provide additional integration coverage; pytest is not
installed in the Ubuntu production virtual environment.

## Next engineering work

Keep ClamAV as the working on-demand file scanner. Before treating behavioral
alerts as dependable protection, evaluate a detector trained for this host's
normal workload, with separate later normal sessions and controlled attack
tests. The current tests establish the collection fault and environment mismatch;
they do not establish a safe replacement model. Any self-traffic filtering must
be applied consistently to training and inference and evaluated for blind spots,
rather than simply suppressing processes that currently generate alerts.
