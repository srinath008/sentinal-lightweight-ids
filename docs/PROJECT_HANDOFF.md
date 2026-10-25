# Current local deployment — 2026-10-17

Read WSL_ADAPTATION_REPORT.md and the latest PROJECT_STATUS.md entry first.
Local Ubuntu uses an experimental profile-union SVM with a checked original
backup. The source historical model and public download still use the original
SVM; do not inadvertently overwrite the adapted local model with the source
fallback during future installation work. Aggregate development sessions and
the adapted artifact are preserved in ids_dataset/host_adaptation_20261017/ and
models/output/host_adapted_20261017/. Three adaptive rounds and their limitations
are documented. Current regression suite: 44 passed, one Windows skip.

# Sentinel application update — 2026-10-13

The current detector is now integrated into `desktop/` (local web UI with an
optional pywebview native window). `release_tools/` builds and installs a Linux
preview; `landing/` provides a download page and actual release archive. See
`docs/APP_INSTALL.md`. Raw logs and the selected model were not modified.

Verified: 103 tests; package replay on Ubuntu WSL 2/Python 3.12 and Windows.
Both reproduce 600 scored windows, 255 flagged. UI browser checks passed after
fixing the chart's SVG hidden state. Linux venv support was installed for an
isolated test. Full installation/native window/live CO-RE collection remain
open; WSL kernel BTF is present but collectors and pkexec are absent.

---

# Project Handoff: eBPF-Based Host Intrusion Detection System

> 2026-10-02 extension: this document preserves the original background and
> planned packages. Consult the correction at the top of PROJECT_STATUS.md,
> CROSS_SESSION_RESULTS.json, and NEXT_STEPS_LINUX.md for current implementation
> and verified limitations. New development uses corrected shared-origin
> features and versioned model bundles; old model artifacts are historical.

**Document purpose:** This is a self-contained handoff document for an AI coding agent (Claude Code, Antigravity, Codex, or similar) picking up this project with no prior conversational context. Every claim below reflects what has actually been verified in this project's history — where something has *not* been verified or confirmed, it is explicitly flagged as such rather than assumed.

**Scope note:** This document covers **only** the eBPF host intrusion detection system (an Operating Systems course project). The same team is also running a separate, unrelated Computer Networks course project (WiFi CSI-based occupancy sensing on ESP32 hardware). That project is out of scope here and should not be conflated with anything below.

---

## Table of Contents

1. [Project Background](#1-project-background)
   - 1.1 [Overview & Purpose](#11-overview--purpose)
   - 1.2 [Problem Statement](#12-problem-statement)
   - 1.3 [Tech Stack & Dependencies](#13-tech-stack--dependencies)
   - 1.4 [Architecture & Constraints](#14-architecture--constraints)
   - 1.5 [Hardware Topology](#15-hardware-topology)
   - 1.6 [References & Resources](#16-references--resources)
2. [Work Completed to Date](#2-work-completed-to-date)
   - 2.1 [Environment Setup — IdeaPad (Ubuntu)](#21-environment-setup--ideapad-ubuntu)
   - 2.2 [eBPF Toolchain Build](#22-ebpf-toolchain-build)
   - 2.3 [Data Collection Orchestration Script](#23-data-collection-orchestration-script)
   - 2.4 [Data Collection Sessions Inventory](#24-data-collection-sessions-inventory)
   - 2.5 [Raw Data Format Reference](#25-raw-data-format-reference)
   - 2.6 [Known Issues & Technical Debt](#26-known-issues--technical-debt)
   - 2.7 [Cross-Machine Transfer Setup (SSH)](#27-cross-machine-transfer-setup-ssh)
   - 2.8 [Version Control Status](#28-version-control-status)
   - 2.9 [Other Deliverables Produced](#29-other-deliverables-produced)
3. [Remaining Work — Agent Work Packages](#3-remaining-work--agent-work-packages)
   - 3.0 [Global Constraints (apply to every work package)](#30-global-constraints-apply-to-every-work-package)
   - WP-00 [Verify Data Transfer & Directory Structure](#wp-00-verify-data-transfer--directory-structure) — **mandatory first step**
   - WP-01 [Initialize Version Control](#wp-01-initialize-version-control)
   - WP-02 [TUF Python Environment Setup](#wp-02-tuf-python-environment-setup)
   - WP-03 [Raw Log Parsing & Schema Validation Utilities](#wp-03-raw-log-parsing--schema-validation-utilities)
   - WP-04 [Phase-Label Joining](#wp-04-phase-label-joining)
   - WP-05 [Feature Engineering (Windowed Aggregation)](#wp-05-feature-engineering-windowed-aggregation)
   - WP-06 [Exploratory Sanity Checks](#wp-06-exploratory-sanity-checks)
   - WP-07 [Model Training — Isolation Forest](#wp-07-model-training--isolation-forest)
   - WP-08 [Model Training — One-Class SVM](#wp-08-model-training--one-class-svm)
   - WP-09 [Model Evaluation & Comparison](#wp-09-model-evaluation--comparison)
   - WP-10 [Optional: Third Baseline Collection Session](#wp-10-optional-third-baseline-collection-session)
   - WP-11 [Real-Time Inference Pipeline](#wp-11-real-time-inference-pipeline)
   - WP-12 [Documentation & Final Report Update](#wp-12-documentation--final-report-update)
   - 3.13 [Suggested Execution Order & Parallelization](#313-suggested-execution-order--parallelization)
   - 3.14 [Human Decision Points](#314-human-decision-points)
   - 3.15 [Security, Rate-Limit & Resource Constraints Recap](#315-security-rate-limit--resource-constraints-recap)

---

## 1. Project Background

### 1.1 Overview & Purpose

This is a university Operating Systems course project (Semester 3) built by a 4-person student team. It implements a lightweight **host-based intrusion detection system (IDS)** that:

- Captures live system activity at the **syscall level** using **eBPF** (process execution, file opens, TCP connections).
- Detects anomalous behavior using **unsupervised machine learning** (Isolation Forest, One-Class SVM) — trained only on "normal" system behavior, with no labeled attack data required at training time.
- Is intended as a proof-of-concept / academic demonstration, not a production security product. Intended end users are the course faculty (as evaluators) and, secondarily, the student team itself as a learning exercise in systems programming, eBPF, and applied ML.

### 1.2 Problem Statement

Existing syscall-based IDS research commonly relies on the **ADFA-LD** dataset, which is over a decade old and does not reflect modern OS/kernel behavior or modern attack techniques. The team's explicit framing (used in their literature review) is that **dataset staleness is a research gap**, and that collecting a fresh, self-sourced syscall dataset on real, current hardware is itself a meaningful contribution — independent of final model accuracy. This framing should be preserved in any future documentation or reporting the agent produces.

### 1.3 Tech Stack & Dependencies

**Data collection (implemented, on Ubuntu):**
- Ubuntu 26.04 LTS ("Resolute"), kernel `7.0.0-31-generic`
- `bpf` / `libbpf-tools` (CO-RE, built from source — see §2.2)
- `clang`/`llvm` (v21 toolchain), `bpftool`
- Bash (collection orchestration script)
- `nmap` (attack simulation only — recon phase)

**ML / feature engineering (not yet started — planned):**
- Python 3.x
- Expected libraries: `pandas`, `numpy`, `scikit-learn` (Isolation Forest and One-Class SVM are both in `sklearn.ensemble` / `sklearn.svm`), likely `matplotlib`/`seaborn` for evaluation plots
- **None of these are confirmed installed on the TUF yet** — see WP-02.

**No web framework, database, or frontend is part of this project's scope.**

### 1.4 Architectural Decisions & Constraints

- **CO-RE over classic BCC compilation:** The team originally tried `bpfcc-tools` (apt package), which runtime-compiles eBPF programs against live kernel headers via clang. This failed on the very recent kernel (`7.0.0-31`) due to a `static_assert` mismatch on `struct filename` layout — a known class of fragility in that approach on bleeding-edge kernels. The team switched to **CO-RE (Compile Once – Run Everywhere) libbpf-tools**, which use BTF (`/sys/kernel/btf/vmlinux`) at runtime instead of compiling against kernel headers. This is more portable and is the direction upstream BCC itself has been moving. **Any future eBPF tooling added to this project should follow the same CO-RE approach, not classic BCC.**
- **Hardware isolation:** Attack simulation tooling (port scanning, privilege-escalation enumeration, filesystem access to sensitive paths) is deliberately run only on a **dedicated, non-daily-driver machine** (the IdeaPad), never on the ML training machine. This is a stated safety/isolation principle for the project and should not be casually violated by future automation.
- **Localhost-only attack simulation:** All simulated network reconnaissance targets `127.0.0.1` only. No external hosts are ever scanned. This must be preserved in any modification to the collection script.
- **Unsupervised approach chosen deliberately:** to avoid the cost/impracticality of hand-labeling large volumes of real attack data, and because it generalizes better to *unknown* attack types than a supervised classifier trained only on the specific simulated attacks.

### 1.5 Hardware Topology

| Machine | Role | OS | Key specs | Network |
|---|---|---|---|---|
| Lenovo IdeaPad 330 | Data collection + attack simulation (sandboxed) | Ubuntu 26.04 LTS, kernel 7.0.0-31 | Older/lower-spec hardware (HDD, limited RAM) | Home Wi-Fi, DHCP |
| ASUS TUF F16 | ML training, feature engineering, report/deck work | Windows | i7-14650HX, RTX 5060 | Home Wi-Fi, DHCP, IP observed as `192.168.1.7` at time of writing — **DHCP-assigned, may change; do not hardcode without verifying current IP first** |

Both machines are on the same home LAN. SSH (OpenSSH Server, native Windows feature) has been installed and enabled on the TUF to allow direct `scp` transfer from the IdeaPad — see §2.7.

### 1.6 References & Resources

**None currently exist.** No design document, API specification, architecture diagram, or external wiki has been created for this project as of this handoff. The only artifacts are:
- The collection script and raw datasets described in Section 2.
- One faculty-facing progress report (`.docx`, see §2.9) — human-readable summary, not a technical spec.

If an agent produces design documentation going forward, it should be committed to the (currently nonexistent — see WP-01) repository, not left as ephemeral chat output.

---

## 2. Work Completed to Date

### 2.1 Environment Setup — IdeaPad (Ubuntu)

- Ubuntu 26.04 LTS installed and running kernel `7.0.0-31-generic`.
- Build toolchain installed: `clang-21`, `llvm-21`, `gcc`/`g++`, `build-essential`, `libelf-dev`, `libzstd-dev`, `libcap-dev`, `pkg-config`, `zlib1g-dev`, `libssl-dev`.
- `nmap` installed (required for attack-simulation recon phase).
- Auto-suspend was disabled on this machine to prevent multi-hour unattended collection runs from being interrupted (manual OS setting change — not scripted, so a fresh OS install would need this redone manually via Settings → Power).

### 2.2 eBPF Toolchain Build

- Repository cloned: `https://github.com/iovisor/bcc.git` (with `--recurse-submodules`) into `~/bcc` on the IdeaPad.
- Built via `cd ~/bcc/libbpf-tools && make`, producing static CO-RE binaries at `~/bcc/libbpf-tools/` including `execsnoop`, `opensnoop`, and `tcpconnect` (plus many others built as a side effect of the shared Makefile, which are unused by this project).
- Two build-time issues were hit and resolved during this process:
  - Missing `libssl-dev` (bpftool's bundled signing feature needs OpenSSL headers) → installed.
  - `asm/errno.h` not found when compiling for the BPF clang target, a known multiarch header-path quirk → fixed with `sudo ln -sf /usr/include/x86_64-linux-gnu/asm /usr/include/asm`.
- **Verified working** (manually confirmed via `sudo ./execsnoop` etc. printing expected headers and live output): `execsnoop`, `opensnoop`, `tcpconnect`.
- **Known limitation:** BTF is required at `/sys/kernel/btf/vmlinux` (confirmed present, ~7 MB) for these binaries to function. A different kernel build lacking `CONFIG_DEBUG_INFO_BTF` would break this — not currently a problem, but worth being aware of if the OS is ever reinstalled/upgraded.

### 2.3 Data Collection Orchestration Script

**File:** `collect_dataset.sh` — currently located at `~/Downloads/collect_dataset.sh` on the IdeaPad (chmod +x applied). **This file is not yet committed to any version control system** (see §2.8/WP-01) — its only authoritative copy is on the IdeaPad's local disk plus this handoff's accompanying chat history.

**What it does**, in order:
1. Resolves the real invoking user's home directory via `SUDO_USER`/`getent passwd` (deliberately does **not** rely on `sudo -E`, since the sudoers policy on this machine does not honor full environment preservation).
2. Verifies prerequisites: must be run as root, `nmap` must be installed, and `execsnoop`/`opensnoop`/`tcpconnect` binaries must exist at `~/bcc/libbpf-tools/`.
3. Starts all three snoop tools **once**, continuously, for the entire session (never restarted mid-run, to avoid losing events at phase boundaries). Each raw output line is prefixed with a timestamp using bash's built-in `$EPOCHREALTIME` (deliberately **not** a forking `date` call — see §2.6 for why) and written to `<name>.csv` in the session output directory.
4. Runs four sequential phases, each writing a `phase,start_epoch,end_epoch` row to `phase_log.csv`:
   - **`baseline`** (default 3600s / 60 min): no injected activity — just whatever the operator is doing on the machine at the time.
   - **`attack_recon`** (default 900s / 15 min): loops `nmap` scans against `127.0.0.1` only (TCP connect scan, service version scan, UDP top-ports scan), sleeping 5s between iterations.
   - **`attack_privesc`** (default 900s / 15 min): loops privilege-escalation **enumeration** only (no actual exploitation) — `sudo -l`, `find / -xdev -perm -4000/-2000`, `cat /etc/sudoers`, `getcap -r /` (see §2.6 — this one is **not** `-xdev`-scoped and is a known issue), `id`, `cat /etc/passwd`.
   - **`attack_fileaccess`** (default 900s / 15 min): loops suspicious file-access patterns — reads `/etc/shadow`, `$REAL_HOME/.ssh/id_rsa`, searches home directory for key/password/secret-named files, greps `/etc` for "password", reads recently modified files under `/var/log`.
5. On any exit path (normal completion, Ctrl+C, terminal close, or error), a `trap cleanup EXIT INT TERM` guarantees all capture processes and any still-running attack-simulation loop are killed — nothing can be left running in the background.
6. Output lands in a fresh timestamped directory: `~/ids_dataset/<YYYYMMDD_HHMMSS>/`, containing `execsnoop.csv`, `opensnoop.csv`, `tcpconnect.csv`, `phase_log.csv`, and `.err` files per tool (stderr capture).

**Usage:** `sudo ~/Downloads/collect_dataset.sh` (no `-E` needed; the script resolves the real home directory itself).

### 2.4 Data Collection Sessions Inventory

Three collection runs have occurred; **only two are valid for training.**

| Session folder | Status | Baseline activity | Notes |
|---|---|---|---|
| `20260913_142059` | ⚠️ **INVALID — do not use** | Idle-ish | Collected *before* the timestamp-feedback-loop bug (§2.6) was found and fixed. `execsnoop.csv` from this run is ~99.6% contaminated with a single repeating `date` process and is not usable. `opensnoop.csv`/`tcpconnect.csv` from this same run were not independently re-verified after the bug was found and should be treated as suspect until checked. **This folder may still exist on disk (both on the IdeaPad and possibly transferred to the TUF) and must be explicitly excluded or deleted — see WP-00.** |
| `20260914_120411` | ✅ Verified clean | Idle / light usage | Post-fix rerun. All four phases verified present with correct process-name distributions and no timing gaps within attack phases (one small 20s gap exists exactly at the recon→privesc phase transition, which is expected). |
| `20260916_185643` | ✅ Verified clean | YouTube video streaming + multiple browser tabs open | Deliberately different baseline activity from session 1, to add behavioral diversity. Verified: browser/media network activity (`Socket`, `NetworkManager` connections) and cache/streaming file activity (`Cache2`, `Web`, `StreamT~ns` in opensnoop) dominate the baseline window as expected. |

**Exact phase timestamps (epoch seconds, from each session's `phase_log.csv`):**

Session `20260914_120411`:
```
baseline,1789367654.860455,1789371254.870929
attack_recon,1789371254.871726,1789372154.882062
attack_privesc,1789372154.884131,1789373054.894777
attack_fileaccess,1789373054.895465,1789373954.907639
```

Session `20260916_185643`:
```
baseline,1789565206.737966,1789568806.751017
attack_recon,1789568806.762515,1789569706.779934
attack_privesc,1789569706.781987,1789570606.797992
attack_fileaccess,1789570606.798345,1789571506.804265
```

**Approximate row counts observed at verification time** (subject to minor drift if re-verified, but order of magnitude is stable):

| Session | execsnoop.csv | opensnoop.csv | tcpconnect.csv |
|---|---|---|---|
| `20260914_120411` | 10,496 | 8,195,946 | 165,191 |
| `20260916_185643` | 10,804 | 7,777,434 | 164,288 |

The very high `opensnoop` counts are **legitimate but heavily skewed** — see §2.6 for why, and account for this in feature engineering (WP-05) rather than treating it as an error.

### 2.5 Raw Data Format Reference

Every row in every CSV has the shape:

```
<epoch_timestamp_float>,<raw tool output line, space-delimited internally>
```

Only **one comma** is guaranteed per line (separating the injected timestamp from the tool's native output) — everything after that comma is the tool's own fixed-width, space-separated column format, **not further comma-delimited.**

Expected (standard libbpf-tools) column layouts after the timestamp, in order:

- **execsnoop**: `PCOMM PID PPID RET ARGS` (ARGS may itself contain spaces — it is the last field and should be treated as "everything remaining" when parsing, not a fixed-width single token)
- **opensnoop**: `PID COMM FD ERR PATH` (PATH is the last field, same caveat as ARGS above)
- **tcpconnect**: `PID COMM IP SADDR DADDR DPORT`

**⚠️ Agent instruction: do not hardcode these column layouts blindly.** Before writing any parser (WP-03), inspect actual sample lines from each real CSV file with `head -n 20 <file>.csv` and confirm the column count and ordering matches the above. Header rows are **not** written to these files by the collection script — every line is data, including what would look like a header row printed by the tool itself at startup (the very first line of each file is typically the tool's own column-header text, e.g. literally the words `PCOMM PID PPID RET ARGS` — this must be detected and skipped/handled, not parsed as a data row).

### 2.6 Known Issues & Technical Debt

1. **[FIXED, but historically relevant] Timestamp feedback-loop bug.** The original version of the collection script used `$(date +%s.%N)` inside the per-line logging loop. Because starting the `date` process is itself a process-execution event, it was being captured by `execsnoop`, which triggered another `date` call to timestamp *that* event, and so on — an unbounded feedback loop. This produced a dataset that was 99.6% artifact noise (session `20260913_142059`). **Fixed** by switching to bash's non-forking built-in `$EPOCHREALTIME`. All sessions collected after this fix are clean of this specific issue. **Any future modification to the logging loop must not reintroduce a forking command inside it.**

2. **[UNRESOLVED] `getcap -r /` and unscoped `find /` calls in the `attack_privesc` phase dominate `opensnoop` volume.** Unlike the `find` calls (which were scoped with `-xdev` to exclude `/proc`/`/sys`), the `getcap -r /` call recursively scans the **entire real filesystem** on every loop iteration. On the IdeaPad's HDD, a single such scan likely takes far longer than the 5-second sleep between loop iterations, meaning the privesc phase's `opensnoop.csv` volume is dominated by a small number of exhaustive, monolithic filesystem crawls rather than many varied short bursts. This is real, correctly-labeled data (not corrupted), but it means the privesc feature distribution will be less diverse than intended. **Recommended but not yet implemented fix:** scope `getcap` the same way as `find`, e.g. `find / -xdev -type f -exec getcap {} \; 2>/dev/null`, in any future collection run.

3. **[UNRESOLVED] Only two baseline behavioral profiles collected** (idle, and media-streaming). A third profile — genuine development/compilation workload — was planned but has **not** been executed as of this handoff (see WP-10, marked optional/conditional). The team's own stated plan was to first attempt feature engineering and model training with the current two-session dataset, and only add a third session if evaluation results show the model needs more baseline diversity to reduce false positives.

4. **[NEEDS VERIFICATION] Dataset transfer completeness and directory structure not independently confirmed.** See WP-00 — this is the mandatory first task for whichever agent picks this up next.

5. **[NEEDS VERIFICATION] `upowerd` (Linux power management daemon) and `sd_espeak-ng`/`sd_espeak-ng-mb` (speech synthesis engine) appeared as high-frequency `opensnoop` processes during the streaming baseline session.** `upowerd` polling is plausibly explained by normal charging/battery-status behavior and is likely fine to keep as real background noise. The espeak processes were **not explained or investigated** — it is unknown whether this was an intentional accessibility feature, an app-triggered TTS event, or something unexpected. Flag for human review if it recurs or seems anomalous in feature analysis (see §3.14).

### 2.7 Cross-Machine Transfer Setup (SSH)

- OpenSSH Server was **not originally installed** on the TUF (Windows). It was installed via:
  ```powershell
  dism /online /Add-Capability /CapabilityName:OpenSSH.Server~~~~0.0.1.0
  Start-Service sshd
  Set-Service -Name sshd -StartupType Automatic
  ```
- An inbound firewall rule (`OpenSSH-Server-In-TCP`) existed but was initially scoped to the `Private` network profile only. The TUF's active Wi-Fi network was classified as `Public` by Windows, silently blocking all connections. Fixed via:
  ```powershell
  Set-NetFirewallRule -Name OpenSSH-Server-In-TCP -Profile Any
  ```
- SSH login as user `srinath` on the TUF at `192.168.1.7` was confirmed working (interactive password login, no key-based auth configured).
- **A `scp` transfer command was issued** (`scp -r ~/ids_dataset/ srinath@192.168.1.7:E:/ids_dataset/`) but **its successful completion and the resulting directory structure were not confirmed in this conversation.** Notably: since the source path had a trailing slash but `scp` (unlike `rsync`) still nests the source directory name under the destination, the actual result may be a **nested** `E:/ids_dataset/ids_dataset/<session folders>/` rather than the flat `E:/ids_dataset/<session folders>/` that was intended. **This must be checked as part of WP-00.**
- No SSH key pair has been generated/exchanged — all access is password-based. This is acceptable for a local home-LAN academic project but is noted as a fragility (password prompts block full automation) — see WP-01/WP-02 environment notes.

### 2.8 Version Control Status

**No git repository has been initialized for this project.** All code (the collection script, and this handoff document itself) currently exists only as: (a) manually-placed files on the IdeaPad and/or TUF filesystems, and (b) chat-session artifacts. There is no commit history, no staged changes, and no remote. **Establishing version control is Work Package 01 and should be treated as a near-immediate priority** — without it, any agent work on this project going forward has no safety net against accidental loss or overwrites.

### 2.9 Other Deliverables Produced

- `OS_Project_Progress_Report.docx` — a short faculty-facing progress report summarizing project purpose, work completed, challenges/resolutions, and remaining work at a non-technical level. This is a human-readable summary document, not a technical spec, and should not be treated as a substitute for this handoff document. Location: wherever the student saved their chat download (not tracked in any project directory).

---

## 3. Remaining Work — Agent Work Packages

### 3.0 Global Constraints (apply to every work package)

- **Never** run attack-simulation tooling (port scans, privilege-escalation enumeration, sensitive-file reads) on any machine other than the designated sandboxed IdeaPad. Never target any host other than `127.0.0.1` for simulated network reconnaissance.
- **Never** commit raw credentials, SSH keys, or `/etc/shadow`-derived content to version control, even though reading `/etc/shadow` is an intentional part of the simulated attack data — the *presence of a syscall event referencing that path* is the training signal, not its contents. Feature engineering must never carry actual file contents into the feature vectors or into any committed artifact — only metadata (which path, when, by which process).
- **Never** modify `collect_dataset.sh`'s safety properties (the `trap cleanup` handler, the `-xdev` filesystem scoping on the `find` calls, or the `127.0.0.1`-only nmap targets) without explicit human sign-off — these were deliberate safety decisions, not incidental implementation details.
- All new Python code should target Python 3.10+ compatibility (exact version to be confirmed as part of WP-02) and should not assume any package is installed without checking the environment first.
- All new scripts/notebooks must be **idempotent** where feasible (safe to re-run without duplicating output or corrupting prior results) — this dataset took real wall-clock time to collect and must not be silently overwritten by a careless script.

---

### WP-00: Verify Data Transfer & Directory Structure

**This is a mandatory prerequisite for every other work package that touches data (WP-03 onward). Do not skip.**

- **Success criteria:** The agent has produced and reported an accurate, verified map of exactly which session folders exist on the TUF, at exactly which path, containing exactly which files, with confirmed non-zero, sane row counts.
- **File paths involved:** `E:\ids_dataset\` on the TUF (Windows) — exact subpath to be discovered, not assumed, per below.
- **Dependencies:** None. This is the first task.
- **Steps:**
  1. On the TUF, list the contents of `E:\ids_dataset\` (e.g. `Get-ChildItem -Recurse E:\ids_dataset` in PowerShell, or equivalent).
  2. Determine whether the data landed flat (`E:\ids_dataset\20260914_120411\...`) or nested (`E:\ids_dataset\ids_dataset\20260914_120411\...`) — see §2.7 for why this ambiguity exists. If nested, flatten it (move the inner contents up one level) so all downstream paths in this document's work packages resolve correctly.
  3. Confirm the presence of exactly these two valid session folders: `20260914_120411` and `20260916_185643`, each containing `execsnoop.csv`, `opensnoop.csv`, `tcpconnect.csv`, and `phase_log.csv`.
  4. If the invalid session folder `20260913_142059` is present, **delete it** (or move it to a clearly-named `invalid_sessions/` subfolder if the human wants it kept for the report's "challenges encountered" narrative — ask before deleting if uncertain; see §3.14).
  5. For each of the two valid session folders, run a row count (`wc -l` equivalent) on all four files and confirm counts are non-zero and roughly consistent with §2.4's table (exact counts may differ slightly if the source folder was re-verified, but should be the same order of magnitude — a 10x+ discrepancy indicates a transfer problem and should be flagged).
  6. Report the final confirmed directory layout back before proceeding to any other work package.
- **Testing requirement:** No automated test needed; this is a verification/reporting step. The "test" is the accuracy of the reported directory map.
- **Flag for human review if:** the data is missing entirely, row counts are wildly inconsistent with §2.4, or there is any ambiguity about which folder is which session.

---

### WP-01: Initialize Version Control

- **Success criteria:** A git repository exists containing, at minimum, `collect_dataset.sh` and this handoff document, with an initial commit made.
- **File paths:** Repository root location to be decided by the human or defaulted to a new folder on the TUF, e.g. `~/ebpf-ids-project/` (Windows equivalent path). Suggested structure:
  ```
  ebpf-ids-project/
  ├── collection/
  │   └── collect_dataset.sh
  ├── docs/
  │   └── PROJECT_HANDOFF.md
  ├── feature_engineering/    (populated by WP-03 onward)
  ├── models/                 (populated by WP-07/WP-08)
  └── README.md
  ```
- **Dependencies:** WP-00 must be complete first (so the repo structure can correctly reference verified data paths, even though raw data itself should **not** be committed — see below).
- **Steps:**
  1. `git init` in the chosen project root.
  2. Create a `.gitignore` that excludes raw data (`*.csv` under any `ids_dataset`-like path, and any large binary artifacts) — raw syscall data should not live in git history; only code, docs, and small derived summary files should be tracked.
  3. Copy `collect_dataset.sh` (from the IdeaPad, or from this handoff's description if the original file needs to be reconstructed) into `collection/`.
  4. Copy this handoff document into `docs/`.
  5. Write a minimal `README.md` linking to the handoff doc.
  6. Make an initial commit with a clear message (e.g. `Initial commit: collection script + project handoff doc`).
- **Testing requirement:** `git log` shows one commit; `git status` is clean afterward.
- **Flag for human review:** whether to also set up a remote (GitHub/GitLab) for the team's other members to collaborate — this handoff has no information about whether the other 3 team members have their own copies of anything, so assume they do not until told otherwise.

---

### WP-02: TUF Python Environment Setup

- **Success criteria:** A working Python environment on the TUF with `pandas`, `numpy`, `scikit-learn`, and `matplotlib` importable, isolated from any system Python.
- **Dependencies:** None (can run in parallel with WP-01).
- **Steps:**
  1. Confirm Python 3 is installed on the TUF (`python --version` or `python3 --version`); install if missing.
  2. Create a virtual environment, e.g. `python -m venv .venv` inside the project root established in WP-01.
  3. Activate it and install: `pip install pandas numpy scikit-learn matplotlib jupyter`.
  4. Freeze the environment: `pip freeze > requirements.txt`, and commit that file (WP-01's repo).
  5. Verify with a one-line smoke test: `python -c "import pandas, numpy, sklearn, matplotlib; print('OK')"`.
- **Testing requirement:** The smoke-test command above must print `OK` with no errors.

---

### WP-03: Raw Log Parsing & Schema Validation Utilities

- **Success criteria:** A Python module that can load any of the three raw CSV types (execsnoop, opensnoop, tcpconnect) from any verified session folder into a clean `pandas.DataFrame` with correctly typed, named columns — with unit tests proving it handles the header-line-as-first-row quirk (§2.5) correctly.
- **File paths:** `feature_engineering/parsing.py` (new file); tests in `feature_engineering/tests/test_parsing.py` (new file).
- **Dependencies:** WP-00 (needs confirmed real file paths), WP-02 (needs the Python environment).
- **Expected inputs:** Raw `.csv` files as produced by `collect_dataset.sh` (format per §2.5).
- **Expected outputs:** `pandas.DataFrame` objects with columns:
  - execsnoop → `timestamp` (float), `pcomm` (str), `pid` (int), `ppid` (int), `ret` (int), `args` (str)
  - opensnoop → `timestamp` (float), `pid` (int), `comm` (str), `fd` (int), `err` (int), `path` (str)
  - tcpconnect → `timestamp` (float), `pid` (int), `comm` (str), `ip` (int, IP version 4 or 6), `saddr` (str), `daddr` (str), `dport` (int)
- **Steps:**
  1. Load 20 raw lines from each of the two valid sessions' three file types (six files total) using `head`, and manually confirm the real column layout matches §2.5's expected schema (do **not** assume — verify).
  2. Write a `load_execsnoop(path: str) -> pd.DataFrame`, `load_opensnoop(path: str) -> pd.DataFrame`, `load_tcpconnect(path: str) -> pd.DataFrame` function per file type.
  3. Each loader must: split off the timestamp on the first comma; detect and skip the tool's own header line (the first data-looking line whose content matches the literal column-name header text rather than real data — e.g. a line where the "pid" field is not numeric); parse the remainder into the correct number of whitespace-separated fields, treating the final column (`args`/`path`) as "everything remaining" so that embedded spaces are preserved.
  4. Write unit tests using small hand-crafted fixture files (a handful of representative lines, including one header line and one line with a multi-word `args`/`path` value) — do not rely on the full multi-million-row real files for unit tests.
  5. Run the loaders against the two real verified sessions and confirm no parse errors, and that resulting row counts match the `wc -l` counts from WP-00 (minus one row per file for the skipped header line).
- **Testing requirement:** `pytest feature_engineering/tests/` must pass. Additionally, manually confirm (print or assert) that loading each real file produces zero `NaN` values in required numeric columns (`pid`, `timestamp`, etc.) — any `NaN` there indicates a parsing bug, not real data.

---

### WP-04: Phase-Label Joining

- **Success criteria:** Every row of every parsed DataFrame from WP-03 has an added `phase` column (`baseline`, `attack_recon`, `attack_privesc`, `attack_fileaccess`, or `unlabeled` for anything outside all known phase windows) and a `session_id` column, correctly assigned by timestamp range lookup against that session's `phase_log.csv`.
- **File paths:** `feature_engineering/labeling.py` (new file).
- **Dependencies:** WP-03.
- **Expected inputs:** A parsed DataFrame (from WP-03) plus the corresponding session's `phase_log.csv`.
- **Expected outputs:** The same DataFrame with `phase` and `session_id` columns appended.
- **Steps:**
  1. Load `phase_log.csv` for a given session into a small DataFrame of `(phase, start_epoch, end_epoch)`.
  2. For each row in the raw data DataFrame, find the phase whose `[start_epoch, end_epoch]` interval contains that row's `timestamp`. Use an efficient interval-lookup approach (e.g. `pd.IntervalIndex` or a sorted merge), not a naive per-row Python loop over multi-million-row DataFrames — this must run in a reasonable time (see 3.15 resource constraints).
  3. Rows with no matching interval get `phase = "unlabeled"` — do not drop them; log a count of how many fall into this bucket per session (should be small — just the brief gaps between phases).
  4. Concatenate all sessions' labeled DataFrames together, with `session_id` distinguishing them (e.g. the folder name).
- **Testing requirement:** Unit test with a synthetic `phase_log.csv` and a handful of synthetic timestamps, asserting correct phase assignment at interval boundaries (inclusive/exclusive edge behavior should be explicit and tested, not accidental).

---

### WP-05: Feature Engineering (Windowed Aggregation)

- **Success criteria:** A function that converts labeled, per-event DataFrames (from WP-04) into fixed-time-window feature vectors suitable for `scikit-learn` model input — one row per time window, per session.
- **File paths:** `feature_engineering/features.py` (new file).
- **Dependencies:** WP-04.
- **Expected inputs:** The three labeled event-level DataFrames (execsnoop, opensnoop, tcpconnect) for a given session.
- **Expected outputs:** A single feature DataFrame, one row per `(session_id, window_start, phase)`, with columns including at minimum:
  - `n_exec` — count of execsnoop events in the window
  - `n_unique_pcomm` — count of distinct process names executed in the window
  - `n_open` — count of opensnoop events in the window
  - `n_unique_paths` — count of distinct file paths opened in the window
  - `n_open_errors` — count of opensnoop events with non-zero `err`
  - `n_tcp_connect` — count of tcpconnect events in the window
  - `n_unique_daddr` — count of distinct destination addresses connected to in the window
  - `phase` (carried through as the label, for evaluation only — **must not be used as a model input feature**, since the model is unsupervised)
- **Dataset-specific operations required:**
  - Window size is a tunable parameter — implement it as a function argument (e.g. `window_seconds: float`), not a hardcoded constant. Start with `5.0` seconds as a default per prior discussion, but the function must support experimentation with other values (e.g. `1.0`, `10.0`) without code changes.
  - Windows should be computed **per session independently** (do not create a window that spans the boundary between two different sessions' timestamps, since session 1 and session 2 were collected on different days and their epoch timestamps are not contiguous).
  - Given the known `opensnoop` volume skew during `attack_privesc` (§2.6, item 2), consider (and document the decision either way) whether to cap or log-transform extreme per-window counts so a small number of monolithic filesystem-scan windows don't dominate the feature scale for the entire dataset. **This is a judgment call — flag it for human review if uncertain (§3.14).**
- **Steps:**
  1. Implement `make_windows(df: pd.DataFrame, window_seconds: float) -> pd.Series` that buckets each row's `timestamp` into a window index.
  2. Implement per-source aggregation functions and join them into one wide feature table keyed by `(session_id, window_index)`.
  3. Handle windows where one or more of the three event types has zero events (e.g. a quiet window with opens but no execs) — these must appear as `0`, not be silently dropped.
  4. Save the resulting feature table as `feature_engineering/output/features_window<N>s.parquet` (parquet preferred over CSV for typed, compact storage of a table that will be reloaded repeatedly).
- **Testing requirement:** Unit test with synthetic event data confirming correct window bucketing and correct zero-filling of empty windows. Additionally, sanity-check the real output: total feature-table row count for a session should equal (approximately) `session_duration_seconds / window_seconds`, accounting for the brief unlabeled gaps.

---

### WP-06: Exploratory Sanity Checks

- **Success criteria:** A short notebook or script producing summary statistics and at least one visualization confirming the feature table (WP-05) behaves as expected before any model training is attempted.
- **File paths:** `feature_engineering/notebooks/eda.ipynb` (new file) or equivalent script.
- **Dependencies:** WP-05.
- **Steps:**
  1. Load the feature table and print summary statistics (`.describe()`) grouped by `phase`.
  2. Confirm attack-phase windows show visibly different feature distributions from baseline windows (e.g. `n_tcp_connect` should spike hard during `attack_recon`; `n_open`/`n_unique_paths` should spike during `attack_fileaccess`/`attack_privesc`) — if they do **not** look visibly different, that is a signal something upstream (parsing, labeling, or windowing) is wrong, and the agent should stop and investigate rather than proceeding to model training on broken features.
  3. Plot at least one time-series view of a key feature (e.g. `n_exec` over time, colored by `phase`) across a full session, to visually confirm phase boundaries line up with the data.
- **Testing requirement:** No formal pytest here — this is a human-reviewable diagnostic artifact. The success bar is "the plots make intuitive sense," which should be confirmed by a human before proceeding to WP-07 (see §3.14).

---

### WP-07: Model Training — Isolation Forest

- **Success criteria:** A trained `sklearn.ensemble.IsolationForest` model, trained **only on baseline-phase feature rows**, saved to disk, with anomaly scores computed for all rows (baseline and attack) and stored alongside the feature table for evaluation.
- **File paths:** `models/train_isolation_forest.py` (new file); output model to `models/output/isolation_forest.joblib`.
- **Dependencies:** WP-05 (and ideally WP-06 sign-off).
- **Steps:**
  1. Load the feature table; split rows where `phase == "baseline"` as the training set. **Do not include any attack-phase rows in training** — this is the core unsupervised-learning assumption of the whole project and must not be violated.
  2. Select the feature columns (exclude `session_id`, `window_start`, `phase` from the actual model input — these are metadata/labels, not features).
  3. Fit `IsolationForest` with a documented, explicit choice of `contamination` and `n_estimators` (do not leave these as unexamined defaults — briefly justify the choice in a code comment or the eventual report).
  4. Score **all** rows (baseline and attack) using `.decision_function()` or `.score_samples()`, and store the anomaly score back into the feature table (as a new column, not overwriting anything).
  5. Persist the trained model with `joblib.dump`.
- **Testing requirement:** Assert the model was trained on a non-trivial number of rows (baseline row count > some sane minimum, e.g. > 50) and that scoring produces one score per row with no `NaN`s.

---

### WP-08: Model Training — One-Class SVM

- Mirror of WP-07 using `sklearn.svm.OneClassSVM` instead. Same training-data constraint (baseline-only), same output pattern (scores appended to the feature table, model persisted).
- **File paths:** `models/train_ocsvm.py`; output to `models/output/ocsvm.joblib`.
- **Dependencies:** WP-05.
- **Note:** One-Class SVM is sensitive to feature scaling — unlike Isolation Forest, this model **requires** the features to be standardized/scaled first (e.g. `sklearn.preprocessing.StandardScaler`, fit on baseline data only, then applied to all data). Persist the fitted scaler alongside the model (`models/output/ocsvm_scaler.joblib`), since it will be needed again at inference time (WP-11).

---

### WP-09: Model Evaluation & Comparison

- **Success criteria:** A report (notebook or markdown) comparing both models' ability to separate baseline from each attack phase, with concrete metrics, not just visual impression.
- **File paths:** `models/evaluation.py` or `models/notebooks/evaluation.ipynb`.
- **Dependencies:** WP-07, WP-08.
- **Steps:**
  1. Since ground-truth phase labels exist (even though they weren't used for training), compute standard detection metrics treating `baseline` as the negative class and each attack phase as positive: precision, recall, F1, and ROC-AUC, for both models, at a chosen anomaly-score threshold.
  2. Report false-positive rate on baseline specifically — this is the most actionable metric for a real IDS (how often does it cry wolf during normal use).
  3. Compare the two models side by side in a small results table.
  4. If false-positive rate is high or attack-phase separation is weak, **this is the trigger condition for WP-10** (the optional third baseline session) — document this decision explicitly rather than silently proceeding either way.
- **Testing requirement:** No pytest needed; this is an analysis deliverable. Numbers must be reproducible by re-running the script end to end.

---

### WP-10: Optional: Third Baseline Collection Session

- **Trigger condition:** Only execute this if WP-09's evaluation shows meaningfully high false positives or shows the model has not learned a robust notion of "normal" (per the team's own stated conditional plan — this was never meant to be automatic).
- **Success criteria:** A third, verified-clean session folder capturing a **development/compilation-heavy** workload (the team's own real usage pattern), collected the same way as sessions 1 and 2.
- **File paths:** Runs on the IdeaPad via the existing `~/Downloads/collect_dataset.sh` — no code changes needed unless the `getcap` scoping fix (§2.6 item 2) is also being applied at this time (recommended but not required).
- **Dependencies:** WP-09's findings.
- **Steps:**
  1. On the IdeaPad, open a genuine development environment (e.g. compile a project, run tests, use an IDE/editor actively) to generate representative "dev workload" baseline activity.
  2. Run `sudo ~/Downloads/collect_dataset.sh` as before.
  3. Verify the resulting session folder the same way sessions 1 and 2 were verified (row counts, no `date` contamination, phase timing gaps check, process-name distribution sanity check) — reuse the exact verification commands from §2.4/§2.6, don't reinvent them.
  4. Transfer to the TUF and re-run WP-00's verification for this new folder specifically.
  5. Re-run WP-05 through WP-09 including this third session's baseline data.
- **Flag for human review:** whether this session is worth the ~1h45m collection time versus other ways of addressing false positives (e.g. tuning `contamination`/window size first) — this is a cost/benefit judgment call, not purely technical.

---

### WP-11: Real-Time Inference Pipeline

- **Success criteria:** A running process that reads live output from `execsnoop`/`opensnoop`/`tcpconnect` (or a subset), computes the same feature windows in real time, and scores them against a trained model, producing a live anomaly signal (e.g. printed alert, log line, or simple dashboard).
- **File paths:** `inference/live_pipeline.py` (new file).
- **Dependencies:** WP-07 or WP-08 (a trained, persisted model), and ideally WP-09 (to have picked the better-performing model and a sensible threshold).
- **Steps:**
  1. Reuse the same subprocess-piping pattern from `collect_dataset.sh` (§2.3) to stream live output from the three snoop tools — this must run on the IdeaPad (the machine with the eBPF tooling), **not** the TUF.
  2. Buffer events into rolling time windows matching whatever `window_seconds` was used in the trained model (this value must be read from a config/metadata file saved alongside the model, not hardcoded separately, to avoid the two drifting out of sync).
  3. Compute the same feature vector shape as WP-05 for each completed window, in the same column order.
  4. Load the persisted model (and scaler, if using One-Class SVM) and score each window as it completes.
  5. If the model is running on the IdeaPad but was trained on the TUF, the trained model artifact (`.joblib` file) must be copied back to the IdeaPad first — document this transfer step the same rigorous way WP-00 documents the original data transfer (verify the file arrived, verify it loads correctly).
  6. Emit a clear alert (stdout line at minimum) when a window's anomaly score crosses the chosen threshold, including the timestamp and the feature values that triggered it (for interpretability).
- **Testing requirement:** Run against a short live session on the IdeaPad and manually trigger a known-anomalous action (e.g. an `nmap` scan against `127.0.0.1`) to confirm the pipeline actually flags it in near-real-time. This is inherently a manual/integration test, not a pure unit test.
- **Security/resource note:** This pipeline runs continuously and reads sensitive filesystem/process activity — treat its output logs with the same care as the original raw data (§3.0's constraint about not leaking file contents applies equally here).

---

### WP-12: Documentation & Final Report Update

- **Success criteria:** This handoff document, the repository `README.md`, and the faculty-facing progress report are all updated to reflect whatever was actually completed in WP-00 through WP-11, with the same standard of honesty this document was written with — no claiming a step succeeded without having verified it.
- **Dependencies:** All prior work packages the agent actually completed.
- **Steps:**
  1. Update this document's Section 2 ("Work Completed to Date") to fold in whichever WPs were finished, following the same level of specificity (file paths, verified vs. assumed, known limitations) used throughout this document.
  2. Update or regenerate the faculty progress report with final results (model performance numbers from WP-09), if the human requests a new version for submission.
  3. Do not delete or overwrite this document's historical record of what was already known and fixed (§2.6) — technical debt that gets resolved should be marked resolved, not silently deleted, so the project's history remains legible.

---

### 3.13 Suggested Execution Order & Parallelization

```
WP-00 (mandatory, blocking)
  │
  ├─→ WP-01 (version control)           ─┐
  ├─→ WP-02 (Python env)                 ├─ can run in parallel with each other
  │                                      ┘
  └─→ WP-03 (parsing) ──→ WP-04 (labeling) ──→ WP-05 (features) ──→ WP-06 (EDA, human checkpoint)
                                                                          │
                                                        ┌─────────────────┴─────────────────┐
                                                        ▼                                     ▼
                                                  WP-07 (Isolation Forest)          WP-08 (One-Class SVM)
                                                        │                                     │
                                                        └──────────────┬──────────────────────┘
                                                                       ▼
                                                              WP-09 (Evaluation)
                                                                       │
                                                      ┌────────────────┴────────────────┐
                                                      ▼ (only if triggered)              ▼
                                            WP-10 (3rd session, optional)         WP-11 (Live inference)
                                                      │                                   │
                                                      └─────────────────┬─────────────────┘
                                                                        ▼
                                                                  WP-12 (Docs update)
```

WP-07 and WP-08 are fully independent of each other and can be parallelized. WP-01 and WP-02 can run in parallel with each other and even before WP-00 finishes, though nothing that touches actual data should proceed until WP-00 is confirmed complete.

### 3.14 Human Decision Points

Flag these back to the human rather than deciding unilaterally:

- Whether to delete or archive the invalid `20260913_142059` session folder (WP-00).
- Whether/how to cap or transform the skewed `opensnoop` volume in the `attack_privesc` phase (WP-05).
- Sign-off on the EDA sanity checks (WP-06) before committing to model training compute time.
- Whether the WP-09 evaluation results justify running the optional WP-10 third session, versus tuning existing hyperparameters instead.
- The unexplained `espeak` process activity noted in §2.6 item 5, if it recurs or looks anomalous in any evaluation output.
- Any decision to add other team members' work into this repository once WP-01 establishes it — this document has no visibility into what (if anything) the other 3 team members have independently built.

### 3.15 Security, Rate-Limit & Resource Constraints Recap

- All attack simulation stays on the sandboxed IdeaPad, localhost-only, per §3.0 — this is non-negotiable and not to be relaxed even for testing convenience.
- No external network calls, APIs, or rate-limited services are involved anywhere in this pipeline — all data is locally generated and locally processed. No API keys or credentials are needed for any work package above.
- The IdeaPad is resource-constrained (HDD, limited RAM per §1.5) — any new collection runs (WP-10) or live inference (WP-11) on that machine should avoid running heavy concurrent processes alongside the collection/inference pipeline, per the same reasoning that motivated running Antigravity/IDE-style tooling was rejected earlier in this project's history.
- The TUF has strong compute (RTX 5060) but neither Isolation Forest nor One-Class SVM at this data scale requires GPU acceleration — do not add GPU-dependent dependencies (e.g. `cuML`) unless a future, much larger dataset genuinely requires it.
