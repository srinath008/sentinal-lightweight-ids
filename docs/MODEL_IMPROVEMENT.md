# Improvement using the existing dataset

No new collection was used. The selected detector is One-Class SVM with
`gamma=0.1`, `nu=0.02`, standardized derived features, and a threshold
calibrated on normal validation windows. The model is still trained only
on normal activity. Both idle and browsing/media profiles are represented.

## Fair comparison on the same reserved blocks

| Metric | Reference Isolation Forest | Selected One-Class SVM |
|---|---:|---:|
| Normal-window false-positive rate | 5.97% | 2.56% |
| False-positive windows / 352 normal windows | 21 | 9 |
| Detected simulated attack windows / 248 | 248 | 246 |
| Recall | 100% | 99.19% |
| Precision | 92.19% | 96.47% |
| F1 | 0.9594 | 0.9781 |
| ROC-AUC | 0.9920 | 0.9975 |

False-positive windows decreased by 57.1%, with two additional missed recon
windows. Recon recall is 97.56%; privilege-enumeration and file-access recall
are 100% on retained test windows. These are simulated scripted activities.

The test baseline FPR is 0% in the idle session and 5.11% in the media session.
The combined 2.56% therefore does not mean every workload has that FPR.

The previously reported 53.61% figure used a different experiment: training
only idle activity and testing the entire media session. It is not a direct
before/after comparator for this experiment. The 5.97% reference here uses
the same normal training blocks from both sessions as the improved model.

## What changed

Nineteen configurations were compared across Isolation Forest, One-Class SVM,
Local Outlier Factor, Extra Trees, Random Forest, and logistic regression.
The latter three explicitly use labelled simulation training blocks; they
are comparisons for known scenarios, not baseline-only anomaly detectors.

Selection first requires at least 95% recall in every validation attack phase
and at most 1% validation normal-window FPR. Among qualifying models it
prefers baseline-only learning, then worst-phase recall, F1, and smaller model
size. Selection is recorded before the selected model sees the test blocks.
No candidate selection or threshold adjustment uses the test results.

The seven original input fields are converted to eleven model inputs:
log-scaled activity counts plus open-error proportion, unique-path proportion,
process diversity per execution, and connections per destination. Conversion
is stateless; StandardScaler is fitted only on training baseline windows.
The fitted preprocessing and classifier are saved together for inference.

## Evaluation boundary

Within each phase of each session, the first 50% of windows are assigned to
training, the next 25% to validation, and the final 25% to testing. Two windows
are omitted on both sides of internal boundaries; the first/last two windows
of each phase are also omitted. Both normal profiles appear in each partition.
The model fits 712 normal training windows. Reserved testing has 600 windows.

These are chronological blocks from the same two previously examined
sessions. Repetitive scripted behaviours remain correlated across blocks.
The test blocks are excluded from tuning in this run, but have been examined
in earlier project analysis. This is exploratory within-dataset evidence,
not independent validation on new sessions, a new VM, or actual malware.

Incident grouping requires two consecutive anomaly windows with a 60-second
notification cooldown. Omitted time gaps reset incident state. Rates are
extrapolated from retained test duration, and fragment delays do not measure
the actual beginning of the original attacks. Window-level metrics above are
the primary comparison; grouping does not erase incorrect classifications.

## Artifacts and use

- `models/output/improved/detector_bundle.joblib`: selected pipeline and threshold,
  approximately 7.8 KB. Preserved separately from historical model artifacts.
- `models/output/improved/selection_before_test.json`: validation-only selection.
- `models/output/improved/reserved_test_scores.parquet`: selected test predictions.
- `docs/MODEL_IMPROVEMENT_RESULTS.json`: split manifest, candidates, metrics,
  artifact checksum, and scikit-learn version.

Run from the repository root using the project environment:

```powershell
.venv/Scripts/python.exe -m inference.score_features
```

This writes `inference/output/improved_scores.jsonl` using the saved corrected
feature table. It includes training and validation rows, so use the reserved
test report above for performance claims. It is offline scoring, not scanning
current Windows activity.

Reproduce model selection and evaluation:

```powershell
.venv/Scripts/python.exe -m models.improve_existing
```

The existing raw-log replay and Linux live monitor accept this bundle through
their `--bundle` argument. Live execution and VM compatibility remain unverified.
Use scikit-learn 1.9.1, matching the saved bundle. Exact model disk size alone
does not measure the full Python/runtime or collector memory requirements.

Verification: 89 regression/integration tests passed after the extension,
including split embargoes, feature conversion, both bundle model families,
and incident reset across omitted test gaps.
