# LID-DS 2021 pilot: do not merge this scenario into the current model

The downloaded **CVE-2012-2122 MySQL authentication scenario** was audited and
tested. It gives no convincing improvement for our current detector. The
deployed model and native training data are unchanged. This result applies to
this one scenario and one fixed augmentation trial, not every LID-DS scenario
or every possible detector.

## What was checked

- Archive: 710,616,463 bytes; SHA256
  `33bed8afd1ce0b928bb9cbbff1f49df4d4c5033c9656e5dd4477c67033ec0a6c`.
- All **1,152 recordings**, containing **41,511,610 exported events**:
  210 official training, 60 validation, 882 test recordings, including
  120 recordings with exploit metadata.
- No malformed rows, unresolved feature events, unresolved connect protocols,
  or out-of-order timestamps were reported by this audit. This is a parsing
  result, not proof that the original capture lost no events.
- 27,056 complete five-second diagnostic windows. Final partial windows and
  120 windows crossing attack onset were omitted. 117 attack recordings have
  retained complete windows after onset; three have no such full windows.
- All 9,297 observed connect exits were identified as **UDP**, not TCP, using
  socket creation arguments and descriptor tracking. Counting them as TCP
  would misrepresent our feature definition.

Process activity is overwhelmingly `mysqld`, with a small number of other
process events. These are service/container-oriented recordings, unlike our
whole-laptop collection. This adapter produces an explicitly uncertified
diagnostic view: syscall-based origins, path conventions, collector equivalence
and capture coverage have not been established as identical to native data.
Neither the feature view nor the experimental estimator is deployable through
the native bundle format.

## Fixed comparison

Used the selected SVM's existing settings and native blocked partitions. The
candidate adds **356 normal windows from 177 official external training
recordings** to the 712 native normal training windows. Training uses no attack
labels. The addition is a deterministic sample (seed 2026), deliberately limited
to half the native training count. Both models use the same 1% native baseline
validation calibration target. No hyperparameter or mixture search was run.
The trial specification and thresholds were written before computing test
metrics. The native test blocks were previously examined in this project.

| Native reserved test (352 normal + 248 simulated-attack windows) | Current model | With external normal data |
|---|---:|---:|
| False alarms | 9 | 8 |
| Normal-window false-alarm rate | 2.56% | 2.27% |
| Simulated-attack recall | 99.19% | 99.19% |
| F1 | 0.9781 | 0.9801 |
| Ranking AUC | 0.9975 | 0.9953 |

Native validation remains **3 false positives and 2 missed attack windows** for
both. It fails the predeclared strict validation-improvement gate. Because
quantile calibration at the same 1% target usually fixes the validation false
positive count, this gate alone is not evidence that the dataset is bad. The
other evidence below is the substantive reason for rejecting promotion.

| External official test, diagnostic view | Current model | Augmented model |
|---|---:|---:|
| Normal-window false alarms | 6,266 / 6,266 | 0 / 6,266 |
| Flagged post-onset windows | 18,630 / 18,630 | 0 / 18,630 |

The current model flags every external window, including every normal window;
its apparent 100% attack-exposure detection is therefore not useful detection.
The augmented model flags none. Exposure windows mean time after a recorded
attack onset, **not verified malicious activity in every window**. Do not quote
these numbers as real-malware recall or a rigorous per-window attack benchmark.

## Why more data does not solve this particular mismatch

Five of our seven features are constant zero throughout this scenario:
execution count, unique execution process names, open failures, outgoing TCP
connection count and unique TCP destinations. Every retained post-onset feature
vector also occurs in official normal training data. **18,623 of 18,630**
post-onset windows have all seven features equal to zero; so do 1,412 of 1,680
external normal training windows.

There is attack activity in other channels: the export contains 124,514 accept
exits, 249,023 clone exits, and millions of reads/writes. Those are event counts
over the archive, not counts of successful unique connections or new processes
(clone can produce parent/child exits). Our current feature set does not include
them. A classifier using only these seven values cannot assign different labels
to identical normal and post-onset vectors. Adding these normal examples teaches
the model to accept the same vectors observed during the attacks.

**Decision:** retain this archive and the isolated experiment for research, but
do not merge it into the native training table or replace the current bundle.
One fewer false alarm in 352 native normal windows is too small to establish a
reliable benefit, and the external representation fails to distinguish the
scenario's attack activity. A useful follow-up would require another scenario
with relevant execution/file/outgoing-TCP behaviour, or new collectors/features
for incoming connections, authentication or thread activity. Those require a
separate compatibility and validation exercise.

## Reproduce and inspect

```sh
python -m feature_engineering.lidds_scenario
python -m models.lidds_trial
python -m pytest feature_engineering/tests tests -q
```

Audit output is in `external_data/lidds/audit/`; experimental estimator and
frozen specification are in `external_data/lidds/trial/`. External raw data and
diagnostic artifacts are ignored by Git. Source code and compact reports can be
versioned. No archived payloads or exploit programs were executed.

- Full aggregate counts: LIDDS_AUDIT_SUMMARY.json (per-record audit stays external).
- Metrics, partitions, checksums and overlap: LIDDS_TRIAL_RESULTS.json.
- Acceptance protocol: LIDDS_EXPERIMENT_PROTOCOL.md.
- Original data: [official LID-DS download](https://drive.proton.me/urls/BWKRGQK994#fCK9JKL93Sjm).
- Export semantics: [official exporter](https://github.com/LID-DS/LID-DS/blob/master/lid_ds/export/export.py).

The current bundle SHA256 before and after this trial is
`88167caf3a5250a99810bfb66604defa2425f9fc19e51b175ec22c4ba662b95a`.
