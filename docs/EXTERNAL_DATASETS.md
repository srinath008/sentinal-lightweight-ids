# External dataset compatibility review

**Follow-up completed:** the user supplied CVE-2012-2122.zip locally. All 1,152
recordings were audited and a fixed diagnostic augmentation trial was run.
This scenario is **not approved for merging**: native reserved-test false
positives fell only from 9 to 8, validation did not improve, and the augmented
model flagged none of the external post-onset windows. See LIDDS_TRIAL.md and
LIDDS_TRIAL_RESULTS.json for scope and limitations. The file-access blocker
described below is historical and resolved.

Reviewed 2026-10-10. This project consumes timed process-execution, file-open
(including failures), and TCP-connection events over the whole Linux host.
Its seven features are not generic IDS columns: counts, distinct values,
window boundaries, and collector success/failure semantics must agree.

| Candidate | Finding | Decision |
|---|---|---|
| LID-DS 2021 | Published parser exposes nanosecond timestamps, process/thread identity, syscall direction and arguments. Recordings include syscall text, metadata, resource statistics and packet capture. Container/server workloads differ from desktop host coverage. | Best candidate for a separate external benchmark; not yet approved for merging. |
| ADFA-LD | Syscall sequences cannot supply our timed windows, paths, return codes and TCP destinations. | Requires a separate sequence detector, not appendable to current training. |
| TON_IoT Linux | Official description provides resource/process/network measurements on Ubuntu 14/18, rather than our three event streams. | Separate resource-based benchmark; not appendable. |
| OpTC | Windows endpoint telemetry and different event semantics. | Separate Windows adaptation; not a shortcut to Linux training. |

Sources:
- [LID-DS official repository and current downloads](https://github.com/LID-DS/LID-DS)
- [LID-DS 2021 syscall parser](https://github.com/LID-DS/LID-DS/blob/master/dataloader/syscall_2021.py)
- [LID-DS recording and metadata loader](https://github.com/LID-DS/LID-DS/blob/master/dataloader/recording_2021.py)
- [ADFA official dataset and academic-use terms](https://research.unsw.edu.au/projects/adfa-ids-datasets)
- [TON_IoT official dataset description](https://research.unsw.edu.au/projects/toniot-datasets)
- [OpTC official repository](https://github.com/FiveDirections/OpTC-data)

## Actual access and implementation status

The complete official LID-DS 2021 download is
https://drive.proton.me/urls/BWKRGQK994#fCK9JKL93Sjm. The fragment is necessary:
the earlier truncated link opened a password prompt. Browser access with the
complete link succeeds. Browserless access alone requires JavaScript.

Follow-up test attempt: selected `CVE-2012-2122.zip` (678 MB). Proton's transfer
panel reported Downloaded, but browser download-event/path retrieval timed out
and no readable archive was found in the local download/temporary locations
checked. The recording contents have NOT been inspected. No external recording
has been imported and no augmented-model experiment has run. This is a file
access blocker, not evidence about model performance or dataset quality.

To resume, save that scenario archive locally in `external_data/lidds/` and
inspect the nested recording ZIPs. The scenario archive itself is not a single
recording. Experimental acceptance rules are in LIDDS_EXPERIMENT_PROTOCOL.md.
Published export and loader source was inspected; actual values and semantic
equivalence remain unverified. Do not report improvements from external data.

Added a streaming audit that reads a `.sc` file or one `.sc` member in a ZIP
without extracting the archive, running scenarios, or loading all events
into memory:

```sh
python -m feature_engineering.audit_lidds /path/to/recording.zip --output external/audit.json
# Optional preview only (not a complete recording audit):
python -m feature_engineering.audit_lidds /path/to/recording.zip --limit 100000 --output external/preview.json
```

The report inventories event directions and parameter names, malformed rows,
timestamp order and duration. It deliberately returns
`approved_for_native_training: false`; a syntactically valid file is insufficient.

Before implementing a feature adapter, verify on real recordings:
1. Which exec/open/connect variants are recorded; count each logical event once,
   with the same success/failure rules as our collectors. Entry and exit are
   different records, not two separate calls.
2. How encoded paths and socket destinations are decoded, and whether arguments
   needed to identify TCP are present. Missing measurements must not become zero.
3. Capture boundaries, losses, warmup intervals and attack timestamps from
   metadata. An attack recording need not be malicious for its full duration.
4. Container membership and workload scope. Keep source dataset, recording,
   scenario, and environment IDs; never combine unrelated recordings in a window.
5. Dataset distribution terms separately from framework code licensing.

Use external recordings first as a separate benchmark. Fit preprocessing on
training recordings only; calibrate on separate normal recordings; reserve whole
recordings/scenarios for testing. Compare with native-only training before any
promotion. More server data can worsen desktop false alarms.

## Stronger check on our existing data

`python -m models.transfer_check` reproduces
`docs/WORKLOAD_TRANSFER_RESULTS.json`. It freezes the previously selected SVM
settings, trains on the first 75% of one session's baseline, calibrates a 1%
target FPR on its remaining baseline with four intervening windows excluded,
and tests the other entire session. The IF comparison uses the same partitions
and calibration rule. No attack data enters training/calibration.

| Model | Train normal workload → test workload | Normal-window false alarms | Simulated-attack recall |
|---|---|---:|---:|
| Selected SVM settings | Idle → media | 25.69% | 100% |
| Selected SVM settings | Media → idle | 0.28% | 95.75% |
| Reference IF | Idle → media | 8.47% | 96.86% |
| Reference IF | Media → idle | 0.14% | 2.22% |

These are newly fitted stress-test models, not the deployed bundle (which was
trained with both normal profiles). The IF's high ranking AUC but very low
recall in one direction illustrates threshold-transfer failure. No model is
uniformly best here. These sessions were historically examined, so this is
stronger workload separation, not a new independent validation dataset.

The current bundle remains unchanged. The earlier 2.56% FPR / 99.19% recall
describes blocked testing with both workload profiles represented in training;
it does not establish performance on unfamiliar workloads. External benchmark
results and a Linux VM live smoke test are still outstanding.
