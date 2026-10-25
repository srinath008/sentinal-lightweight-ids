# Linux continuation

Current update: the physical IdeaPad is unavailable. These checks can be
performed in an Ubuntu VM, where collectors monitor the Linux guest only.
An improved existing-data bundle is available at
`models/output/improved/detector_bundle.joblib`; use that path for a controlled
initial smoke test. See MODEL_IMPROVEMENT.md for its measured limits. New
collection is optional future work, not required to use the existing-data bundle.
It still requires Linux live/VM verification and matching scikit-learn 1.9.1.

The Windows development phase implements corrected features, session-separated
training, calibration, incident grouping, and live collection/inference code.
Linux execution, hardware benchmarking, packaging, and file scanning remain.

## First session on the IdeaPad

Open a Codex project on the Ubuntu laptop containing this repository. Read
this file and `docs/PROJECT_STATUS.md`. Preserve the original dataset and
legacy artifacts. Use the SSD for active logs and check free space first.

Verify `uname -a`, `free -h`, `df -h`, `/sys/kernel/btf/vmlinux`, and the actual
CO-RE binary paths. The expected path is `~/bcc/libbpf-tools`; do not assume it.
Test native output headers and event rows against `parse_event` before collection.
This parser targets the existing CO-RE text schemas, not arbitrary BCC variants.

Create a project-local virtual environment using a supported Python version:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-runtime.txt pytest
.venv/bin/python -m pytest feature_engineering/tests tests -q
```

## Collection checks

First run a 30-second baseline capture with a NEW output directory:

```bash
sudo .venv/bin/python -m collection.collect_dataset \
  --tools-dir "$HOME/bcc/libbpf-tools" \
  --output ids_dataset/smoke_new --baseline 30
```

Check manifest status, `.err` files, raw headers, row counts, parser rejects,
CPU/RAM, file ownership, and cleanup after Ctrl+C. Delete nothing automatically.
The three binaries require appropriate privileges; keep the Codex UI itself
running as the ordinary user. Log timestamps are userspace receipt times,
matching the historical capture convention, not kernel occurrence timestamps.
Manifest success alone does not prove zero kernel event loss: inspect stderr
and confirm available lost-event reporting on these binary builds.

Collect several distinct sessions/days including coding/compilation, browsing,
downloads, copying, and multitasking. Some sessions should include real human
usage. Keep Codex quiet during capture to avoid adding development activity.
Reserve entire sessions for validation and test before inspecting their results.

Optional simulations use `--simulate --attack-seconds 900 --interval 5`.
They target `127.0.0.1`, bound enumeration to `/usr/bin` and `/usr/sbin`, and
read synthetic fixture files rather than real credentials. They do not exploit
privileges. Different `--interval` values vary workload intensity. Record the
actual workload/operator activity separately in the experiment notes.

## Corrected features and validated model

```bash
.venv/bin/python -m feature_engineering.replay \
  --session-dir ids_dataset/TRAIN_SESSION \
  --session-dir ids_dataset/VALIDATION_SESSION \
  --session-dir ids_dataset/TEST_SESSION \
  --output feature_engineering/output/features_window5s_v2.parquet

.venv/bin/python -m models.validated_training \
  --features feature_engineering/output/features_window5s_v2.parquet \
  --train TRAIN_SESSION --validation VALIDATION_SESSION --test TEST_SESSION
```

Replace session placeholders with actual directories. Train, validation, and
test session IDs must be disjoint. Each partition needs normal activity, and
test needs simulated scenarios. Do not relabel or split one session into three
IDs to bypass this requirement. The 1% validation baseline FPR target is a
configurable starting point, not a promised test FPR or a chosen product target.
Evaluate detection/false alarms before choosing operating thresholds.

## Live checks (after validated training)

```bash
sudo .venv/bin/python -m inference.streaming \
  --bundle models/output/validated/detector_bundle.joblib \
  --tools-dir "$HOME/bcc/libbpf-tools" --duration 60
```

Score each completed window, including idle windows. Test normal behaviour,
localhost simulation, collector crashes, interruption, event-loss warnings,
and CPU/RAM over longer sessions. Capture output to a file for a bounded test;
production log rotation and a service installer are not implemented yet.
Queue capacity is bounded; exact distinct-value sets grow within each window.
Measure memory during high-cardinality file workloads before calling it lightweight.

The live implementation timestamps events on userspace receipt and uses a
monotonic elapsed clock. It aborts on reported event loss, queue overflow, or
events arriving after their windows are finalized. It discards incomplete
windows on shutdown. Do not interpret these failure modes as a clean verdict.

## Remaining product work

- Validate new data, adjust features only if the evidence justifies it.
- Measure independent-session detection, notifications/hour, detection delay,
  CPU/RAM, and disk use. A second machine is necessary for hardware portability claims.
- Add installation/uninstallation, service lifecycle, bounded retained logs,
  permissions, and readable health/alert UI after live tests pass.
- Add an attributed file-scanning engine for scan-folder functionality.
- Prepare the faculty demo and final report using measured results.

Models are pickle/joblib artifacts: load only trusted project-generated files.
Copy the bundle with its exact scikit-learn version from the training report/runtime.
No actual malware execution is needed for this continuation.
