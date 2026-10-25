# Sentinel application preview

For team revision: [concepts and viva study guide](docs/SENTINEL_TEAMMATE_CONCEPTS_AND_VIVA_STUDY_GUIDE.md).

Full project and presentation context: [complete self-contained report](docs/SENTINEL_COMPLETE_PROJECT_REPORT_AND_PPT_HANDOFF.md).

Final QA (18 October 2026): the installed Ubuntu app passed native startup,
15 browser flow checks, real collector/helper checks, and file scanning.
The full Windows suite passed 117 tests (one Linux-only skip); all 15 Ubuntu
desktop/protection tests passed. Four runtime/display issues were corrected.
Ready for a supervised faculty demonstration as a research prototype; fresh
harmless activity still produced behavioral false alerts. The public download
is an older build. See [final QA and faculty demo steps](docs/FINAL_QA_20261018.md).

Local Ubuntu WSL now has an experimental host-adapted model and HTTP connection
reuse installed. See [measured results and rollback](docs/WSL_ADAPTATION_REPORT.md).
The original source model and public download remain the historical fallback;
the adapted artifact is kept separately in `models/output/host_adapted_20261017/`.

The current model is now integrated into the Sentinel desktop application in
`desktop/`, with a Linux installer in `release_tools/` and a download landing
page in `landing/`. See [installation and limitations](docs/APP_INSTALL.md).

Download page: https://sentinel-linux-ids.srinathb308.chatgpt.site

To preview the interface from this checkout with the existing Python environment:

```bash
python -m desktop.app --browser
```

The landing directory has its own Sites source repository. Keep it separate
from unrelated changes in the parent project repository.

The original source model flags 255 of the 600 recorded replay windows.
The installed Ubuntu adaptation flags 253. Native startup and privileged
collector checks passed on the existing Ubuntu installation; installation
on a clean Linux machine remains unverified.
The existing model is unchanged. This is behavioral detection, not file scanning.

# eBPF behaviour-based intrusion detection prototype

## Existing-data improvement

The current selected model is a calibrated One-Class SVM trained on normal
blocks from both existing profiles, with eleven derived inputs. In an
exploratory chronological-block comparison it reduced normal-window false
positives from 5.97% (reference IF) to 2.56%, with simulated-window recall
changing from 100% to 99.19%. Independent-session/VM validation remains open.
See [model improvement details](docs/MODEL_IMPROVEMENT.md) for the protocol,
limitations, saved bundle, and commands. Fast offline scoring:

```bash
python -m inference.score_features
```

The earlier project implementation and independent-session findings below
are preserved as background; the improvement uses a different evaluation split.

An academic Linux security-monitoring project using CO-RE `execsnoop`,
`opensnoop`, and `tcpconnect`, with Isolation Forest and One-Class SVM.
It detects anomalous activity windows. File-virus scanning is a future,
separate component; this ML model does not inspect file contents.

## Current implementation

- Shared five-second windows across all three sources, including idle windows.
- Incremental CSV replay with one active window instead of millions of in-memory rows.
- Strictly disjoint training, validation, and test sessions.
- Baseline-only model/scaler fitting; threshold calibration on validation baseline.
- Versioned model bundle with feature order, transformations (schema), window duration,
  thresholds, and exact scikit-learn version.
- Consecutive-window incident grouping and notification cooldown.
- Linux live-ingestion and collection code, pending hardware integration testing.

The original model artifacts and raw logs are preserved. Their published
F1=0.950 / 0.944 results include normal training data in evaluation and are
historical demonstration numbers. The old training/replay CLI entry points
are retired because old models must not score the corrected feature schema.

## What independent-session checks show

Corrected features were rebuilt from the two original sessions. Fixed-default
thresholds were used without test-based tuning:

| Model | Train on media, test idle: normal FPR | Train idle, test media: normal FPR |
|---|---|---|
| Isolation Forest | 2.92% | 53.61% |
| One-Class SVM | 9.44% | 30.69% |

Isolation Forest detected all simulated attack windows in both folds.
These are repeated scan/enumeration/file-access simulations, not a malware
coverage test. The FPR difference demonstrates insufficient normal workload
coverage. Incident grouping alone does not fix that: the harder IF fold still
produced 37 baseline notifications in one hour at the default grouping policy.

Full results: [cross-session report](docs/CROSS_SESSION_RESULTS.json).
With only two sessions, a final three-way calibrated evaluation is unavailable.
Collect additional independent sessions before training a deployment bundle.

## Development setup

Run commands from the repository root. Python 3.12+ is recommended. Use a
project-local virtual environment; the requirements file below is intentionally
smaller than the historical 115-package environment snapshot.

```bash
python -m venv .venv
# Linux: .venv/bin/python; Windows: .venv/Scripts/python.exe
python -m pip install -r requirements-runtime.txt pytest
python -m pytest feature_engineering/tests tests -q
```

Activate the environment or replace `python` with its absolute executable path.
Windows verification at the initial extension checkpoint: 84 passing tests,
including a synthetic end-to-end training/bundle/inference integration test.

## Replay and evaluation

```bash
python -m feature_engineering.replay \
  --session-dir ids_dataset/20260914_120411 \
  --session-dir ids_dataset/20260916_185643 \
  --output feature_engineering/output/features_window5s_v2.parquet

python -m models.cross_session \
  --features feature_engineering/output/features_window5s_v2.parquet \
  --output docs/CROSS_SESSION_RESULTS.json
```

The rebuild also writes schema metadata and malformed/header counts. It does
not alter raw logs or historical feature/model artifacts. Session IDs are the
input directory names and must uniquely identify collection sessions.

For final training, first build features including fresh independent sessions:

```bash
python -m models.validated_training \
  --features feature_engineering/output/features_window5s_v2.parquet \
  --train TRAIN_SESSION --validation VALIDATION_SESSION --test TEST_SESSION
```

Replace placeholders with actual session IDs. Each partition needs baseline
activity; test needs simulated scenarios. The default 1% validation FPR target
is configurable and does not guarantee a 1% test FPR. Thresholds are never
chosen from test data. Reports distinguish flagged windows from notifications.

```bash
python -m inference.replay \
  --bundle models/output/validated/detector_bundle.joblib \
  --session-dir ids_dataset/TEST_SESSION
```

## Linux continuation

[IdeaPad setup, collection, and live-testing checklist](docs/NEXT_STEPS_LINUX.md)
contains exact commands and remaining checks. CO-RE binaries require Linux,
BTF, and suitable eBPF privileges. Collection timestamps are userspace receipt
times. Output format compatibility and lost-event reporting must be checked
against the actual binary builds.

Live monitoring code uses a bounded queue and incremental windows. It reports
collector failure/loss and aborts on incomplete ingestion. Complete windows
are scored; an unfinished window is discarded at shutdown. Memory for exact
distinct paths remains proportional to each window's unique values and must
be benchmarked on the IdeaPad. Model inference overhead alone does not prove
that the complete application is lightweight.

## Remaining work

Broader normal-use data, genuinely held-out calibration/test sessions, Linux
live integration, CPU/RAM and latency measurements, installer/service/UI,
log rotation, and an attributed file-scanning engine. No actual malware
execution is required for the planned demonstration.

The original background is in docs/PROJECT_HANDOFF.md; corrected current
status is at the top of docs/PROJECT_STATUS.md. Load only trusted joblib bundles.
