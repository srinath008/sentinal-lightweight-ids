# eBPF-Based Host Intrusion Detection System

> **Amrita Vishwa Vidyapeetham — B.Tech AIM, Semester 3**  
> Operating Systems Course Project | Team 2

---

## Overview

A lightweight **host-based intrusion detection system (IDS)** that:

- Captures live system activity at the **syscall level** using **eBPF** (process execution, file opens, TCP connections)
- Detects anomalous behaviour using **unsupervised machine learning** — trained only on normal behaviour, no labeled attack data required
- Built as a proof-of-concept demonstrating the use of fresh, self-sourced syscall data on real current hardware

### Why this matters

Existing syscall-based IDS research relies on the **ADFA-LD** dataset (10+ years old). This project collects a fresh dataset on a real Ubuntu 26.04 / kernel 7.0 machine, which is itself a meaningful contribution independent of model accuracy.

---

## Repository Structure

```
ebpf-detection/
├── collection/              # eBPF data collection script (runs on Ubuntu/IdeaPad)
│   └── collect_dataset.sh
├── docs/                    # Project documentation
│   └── PROJECT_HANDOFF.md   # Full technical handoff — read this first
├── feature_engineering/     # Parsing, labeling, feature extraction (WP-03 → WP-06)
│   ├── parsing.py
│   ├── labeling.py
│   ├── features.py
│   ├── tests/
│   ├── notebooks/
│   └── output/              # Generated .parquet feature tables (gitignored)
├── models/                  # Model training and evaluation (WP-07 → WP-09)
│   ├── train_isolation_forest.py
│   ├── train_ocsvm.py
│   ├── evaluation.py
│   ├── notebooks/
│   └── output/              # Trained .joblib models (gitignored)
├── inference/               # Real-time inference pipeline (WP-11)
│   └── live_pipeline.py
├── requirements.txt         # Python dependencies
└── .gitignore
```

> **Raw dataset (`ids_dataset/`) is NOT committed to this repo** — it lives locally on the TUF at  
> `E:\Amrita Academics\SEM3 AIM\OS\project\ids_dataset\`

---

## Tech Stack

| Layer | Tools |
|---|---|
| Data collection | eBPF CO-RE (`execsnoop`, `opensnoop`, `tcpconnect`), `libbpf-tools`, Bash |
| OS (collection machine) | Ubuntu 26.04 LTS, kernel 7.0.0-31-generic |
| ML / feature engineering | Python 3.x, pandas, numpy, scikit-learn |
| Training machine | ASUS TUF F16 (Windows, RTX 5060, i7-14650HX) |

---

## Dataset

Two verified collection sessions (total ~16M+ events):

| Session | Baseline activity | execsnoop | opensnoop | tcpconnect |
|---|---|---|---|---|
| `20260914_120411` | Idle / light usage | 10,496 | 8,195,946 | 165,191 |
| `20260916_185643` | YouTube + browser | 10,804 | 7,777,434 | 164,288 |

Each session captures 4 phases: `baseline` (60 min) → `attack_recon` → `attack_privesc` → `attack_fileaccess` (15 min each).

---

## Progress

- [x] WP-00 — Dataset transfer verified  
- [x] WP-01 — Version control initialized  
- [ ] WP-02 — Python environment setup  
- [ ] WP-03 — Raw log parsing utilities  
- [ ] WP-04 — Phase-label joining  
- [ ] WP-05 — Feature engineering  
- [ ] WP-06 — Exploratory data analysis  
- [ ] WP-07 — Isolation Forest training  
- [ ] WP-08 — One-Class SVM training  
- [ ] WP-09 — Model evaluation & comparison  
- [ ] WP-10 — Optional 3rd baseline session  
- [ ] WP-11 — Real-time inference pipeline  
- [ ] WP-12 — Final documentation update  

---

## Team

**Team 2 — Amrita AIM SEM3**

---

*For full technical context, architecture decisions, known issues, and work package specifications — see [`docs/PROJECT_HANDOFF.md`](docs/PROJECT_HANDOFF.md).*
