# eBPF-Based Intrusion Detection System

An unsupervised anomaly detection system that passively monitors Linux kernel
events via eBPF tracing tools and detects multi-stage cyber attacks using
Isolation Forest and One-Class SVM.

---

## Project Overview

This system collects three types of kernel-level telemetry using BCC tools:

| Source | Tool | Events captured |
|---|---|---|
| Process execution | `execsnoop` | Every exec syscall — command, PID, return code |
| File access | `opensnoop` | Every open syscall — path, file descriptor, error |
| Network connections | `tcpconnect` | Every outbound TCP connection — IP version, addresses, port |

Events are aggregated into **5-second windows** and scored by two trained models.
A window is flagged as anomalous when it deviates significantly from the
**baseline (normal operation)** behaviour learned during training.

---

## Attack Scenario

The dataset simulates a realistic multi-stage intrusion:

| Phase | Duration | Activity |
|---|---|---|
| `baseline` | 60 min | Normal workload — Firefox browsing, background daemons |
| `attack_recon` | 15 min | `nmap` port scans — burst TCP connection events |
| `attack_privesc` | 15 min | `getcap`/`find` filesystem crawls — massive file access volume |
| `attack_fileaccess` | 15 min | Targeted credential harvesting — elevated exec activity |

---

## Results

Both models trained **only on baseline data** (unsupervised — no attack labels used during training):

| Metric | Isolation Forest | One-Class SVM |
|---|---|---|
| **Precision** | 0.905 | 0.900 |
| **Recall** | **1.000** | 0.993 |
| **F1** | **0.950** | 0.944 |
| **ROC-AUC** | **0.997** | 0.996 |
| **PR-AUC** | 0.990 | **0.997** |

**Per-phase detection rate:**

| Phase | Isolation Forest | One-Class SVM |
|---|---|---|
| `attack_recon` | 100.0% | 97.8% |
| `attack_privesc` | 100.0% | 100.0% |
| `attack_fileaccess` | 100.0% | 100.0% |
| `baseline` (FP rate) | 7.8% | 8.2% |

> **Recommendation:** Use Isolation Forest as the primary detector (perfect recall —
> zero missed attacks). Use the OC-SVM score as a secondary severity signal to
> rank and filter alerts.

---

## Dataset

Collected on a Ubuntu 22.04 VM with BCC tools during two independent sessions:

| File | Session 1 | Session 2 |
|---|---|---|
| `execsnoop.csv` | 10,496 rows | 10,804 rows |
| `opensnoop.csv` | 8,195,946 rows | 7,777,434 rows |
| `tcpconnect.csv` | 165,191 rows | 164,288 rows |

Raw dataset is **not committed** (gitignored). Contact project owner for access.

---

## Tech Stack

- **Python 3.14** — pandas 3.0, scikit-learn 1.9, numpy 2.5, pyarrow 25
- **eBPF / BCC** — execsnoop, opensnoop, tcpconnect (data collection, Linux only)
- **Models** — `sklearn.ensemble.IsolationForest`, `sklearn.svm.OneClassSVM`
- **Storage** — Apache Parquet (feature table + model scores)
- **Tests** — pytest 9.1 — **72 unit tests, 100% passing**

---

## Repo Structure

```
.
├── collection/                   # BCC collection scripts (Linux only)
├── feature_engineering/
│   ├── parsing.py                # Raw CSV loaders (3 eBPF tools)
│   ├── labeling.py               # Phase-label joining via IntervalIndex
│   ├── features.py               # Windowed feature aggregation
│   ├── eda.py                    # Exploratory analysis + plots
│   ├── output/                   # features_window5s.parquet + EDA plots
│   └── tests/                    # 72 unit tests (pytest)
├── models/
│   ├── train_isolation_forest.py # WP-07: IF training
│   ├── train_ocsvm.py            # WP-08: OC-SVM + StandardScaler training
│   ├── evaluation.py             # WP-09: Side-by-side comparison
│   └── output/                   # .joblib models + score parquets (gitignored)
├── inference/
│   └── live_pipeline.py          # WP-11: End-to-end scoring pipeline
├── docs/
│   └── PROJECT_HANDOFF.md        # Full technical specification
├── requirements.txt
└── README.md
```

---

## Quick Start

```bash
# 1. Create and activate the virtual environment
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
.venv\Scripts\Activate.ps1       # Windows PowerShell

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run tests
pytest feature_engineering/tests/

# 4. Build feature table (requires dataset in ids_dataset/)
python feature_engineering/features.py   # not a script — use the pipeline below

# 5. Train models
python models/train_isolation_forest.py
python models/train_ocsvm.py

# 6. Evaluate
python models/evaluation.py

# 7. Run live inference on a session
python inference/live_pipeline.py --session-dir ids_dataset/20260914_120411
```

---

## Progress

- [x] WP-00 — Dataset verification (row counts, schema, phase timestamps)
- [x] WP-01 — Repository structure and version control
- [x] WP-02 — Python environment and dependencies
- [x] WP-03 — Raw log parsing (`parsing.py` — 29 unit tests)
- [x] WP-04 — Phase-label joining (`labeling.py` — 21 unit tests)
- [x] WP-05 — Feature engineering (`features.py` — 22 unit tests)
- [x] WP-06 — Exploratory data analysis (`eda.py` — 4 plot types)
- [x] WP-07 — Isolation Forest training (F1=0.950, ROC-AUC=0.997)
- [x] WP-08 — One-Class SVM training (F1=0.944, ROC-AUC=0.996)
- [x] WP-09 — Model evaluation and comparison report
- [x] WP-11 — Live inference pipeline (`live_pipeline.py`)
- [x] WP-12 — Documentation and final report

---

## Key Engineering Decisions

| Decision | Rationale |
|---|---|
| **log1p on opensnoop counts** | `attack_privesc` crawls generate up to 87k opens/window vs baseline's ~200. log1p prevents scale dominance while preserving ordering |
| **Baseline-only training** | True unsupervised IDS — no attack labels needed. Contamination set to `'auto'` (IF) and `nu=0.05` (OC-SVM) |
| **Right-anchored COMM parsing** | Real data had multi-word process names (`Socket Thread`, `StreamT~ns #132`) — simple split misaligns FD/ERR columns |
| **ERR range constraint (±4096)** | Dataset folder names (e.g. `20260914_120411`) are valid integers but not errno codes — range check prevents misclassification |
| **5-second windows** | Balances temporal resolution vs noise. Tunable via `--window` flag |
| **IF as primary detector** | Perfect recall (zero missed attacks) is critical for a security system |

---

## Authors

Team 2 — Amrita Vishwa Vidyapeetham, SEM3 AIM OS Project
