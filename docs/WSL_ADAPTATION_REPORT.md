# Sentinel host adaptation — completed 2026-10-17

The adapted behavioral model is installed in the local Ubuntu WSL application.
It combines the original normal-only SVM with a local normal-only SVM, accepting
windows that match either normal profile. Every collector event is still counted;
there is no broad process, application or loopback-network whitelist.

## Measured results

| Check | Original model | Installed adaptation |
|---|---:|---:|
| Fresh normal idle windows flagged | 0 / 13 | 0 / 13 |
| Fresh ordinary file/network/system-command windows flagged | 13 / 13 | 0 / 13 |
| Fresh TCP burst windows flagged | 4 / 4 | 4 / 4 |
| Fresh execution burst windows flagged | 4 / 4 | 4 / 4 |
| Fresh file/error burst windows flagged | 4 / 4 | 4 / 4 |
| Historical simulated attack windows detected | 246 / 248 | 246 / 248 |
| Historical normal windows flagged | 9 / 352 (2.56%) | 7 / 352 (1.99%) |
| Historical F1 | 0.978 | 0.982 |

The actual incident grouper produced no incidents in either fresh normal run
and one alertable incident in each fresh stress run. See
WSL_ADAPTED_INCIDENT_CHECK.json. The bursts are harmless unusual workloads, not
malware samples or actual privilege-escalation exploits.

Ubuntu loaded the saved candidate and reproduced all Windows evaluation counts.
Standalone Linux prediction median was 0.35 ms and p95 was 0.61 ms. That process's
peak RSS was approximately 145 MiB including Python/scikit-learn dependencies;
it excludes the GUI, collectors and antivirus engine. The model artifact itself
is 22,225 bytes. See WSL_ADAPTED_RUNTIME_CHECK.json.

## Application improvements

The local HTTP server now reuses browser connections, with explicit message
lengths, socket timeouts, and closure of invalid/unread requests. In sequential
idle checks, dashboard TCP events decreased from an average of 10.96 per
five-second window to zero. This reduces generated activity rather than hiding
observations from the detector. Other system traffic is still included.

The interface reads its model name and historical/local evaluation figures from
the actual installed bundle. It identifies the local model as an experimental
preview and displays raw local sample counts. Network observations now explicitly
include local connections rather than labelling all traffic outbound. Normal
browser disconnects no longer produce noisy server tracebacks.

The earlier multiline-argument collector fix remains enabled in live collection
and was also applied to the dataset collector. All three rounds completed their
collector health checks without malformed/late rows or collector stderr.

## Development history and limits

Three collection rounds scheduled approximately 38 minutes of Linux recordings.
They used aggregate counts only, temporary synthetic files, read-only ordinary
Linux status commands and listeners on loopback. Windows media/browser/Excel use
was background load, not labelled Linux browsing. All temporary workloads and
collectors are stopped; the updated desktop application is open and idle.

Eighteen configurations were fitted in round one, seventeen in round two, and
seventeen in round three. These are repeated candidate fits, not 52 independent
model families. The first selected supervised model had excellent historical
scores but missed new bursts and was rejected. The second adaptation retained
burst detection but flagged two ordinary-command windows and was rejected.
The third used broader normal-command examples and stricter local calibration;
it passed every predefined final gate. See WSL_ADAPTATION_PROTOCOL.md and the
three WSL_ADAPTATION*_RESULTS.json reports for adaptive development details.

This is a small, sequential, single-host experiment. Zero flags in 26 normal
windows is not a guaranteed zero false-alarm rate. Historical simulations have
been examined repeatedly, so their scores are regression evidence, not untouched
independent validation. Earlier normal test rows were explicitly reused as
development data in later rounds; fresh third-round test sessions were excluded
from fitting, calibration and selection. The first 25 windows of the older user
report were assumed normal for development. Its later 26 were not fitted but are
only a retrospective audit, not a fresh ground-truth-labelled test.

Real Ubuntu browsing, development, prolonged use, another device and real-malware
detection remain unvalidated. Seven aggregate activity features cannot establish
malicious intent or reliably distinguish every benign workload from malware.
This local preview supports a better demonstration, not commercial protection
claims or direct monitoring of Windows applications.

## File scanning and validation

Ordinary-user ClamAV scanning was retested with the three existing fixtures:
one harmless EICAR signature detection, no skipped files, and unchanged file
hashes. JSON and readable HTML exports passed. Scan peak RSS remained 999.8 MiB,
additional to the UI/runtime; no ultra-lightweight whole-app memory claim is
justified. See WSL_FILE_SCAN_CHECK.json.

The full automated suite passed 44 tests, with one Linux procfs authorization
test skipped on Windows. Actual Ubuntu runtime/model checks passed. The native
launcher and actual Ubuntu-backed browser UI show the installed model and correct
metrics; proof is saved in app-previews/sentinel-adapted-model.png. Password
authorization and GTK alert delivery had already been human-tested; their logic
was preserved.

## Artifacts and rollback

Active local Ubuntu bundle:
`/opt/sentinel/models/output/improved/detector_bundle.joblib`

Verified original backup:
`/opt/sentinel/models/backups/detector-original-20261017.joblib`

After stopping live monitoring and closing Sentinel, restore it in Ubuntu with:

```bash
sudo install -o root -g root -m 644 \
  /opt/sentinel/models/backups/detector-original-20261017.joblib \
  /opt/sentinel/models/output/improved/detector_bundle.joblib
sentinel
```

The original source model remains unchanged at
`models/output/improved/detector_bundle.joblib`. The adapted source artifact and
frozen selection manifest are retained at `models/output/host_adapted_20261017/`.
Aggregate capture sessions are retained in `ids_dataset/host_adaptation_20261017/`
with separate directories for all three rounds, outside temporary output.

Original SHA-256:
`88167caf3a5250a99810bfb66604defa2425f9fc19e51b175ec22c4ba662b95a`

Active adapted SHA-256:
`f1be5d61c9f198e97df270f015546c28bd5ace1b329814b97f33778e1d25fb8d`

Activation was atomic after checksum, gate and Ubuntu runtime verification.
See WSL_ADAPTATION_DEPLOYMENT.json. No original raw dataset was modified. No
Windows security setting, authentication policy or automatic-update setting was
changed. The public download archive has not been republished with this local
adaptation; it still contains the original model.
