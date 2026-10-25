# LID-DS addition: experiment acceptance protocol

Written before examining downloaded LID-DS event contents or training a model
with them. User authorizes addition only if testing establishes a benefit.

1. Obtain official archived recordings; record source, SHA256, sizes, scenario
   and official training/validation/test membership. Never execute payloads or
   scenario programs; read logs and metadata only.
2. Semantic compatibility is a prerequisite. Check actual exported fields for
   execution, opens and TCP connections against the native collectors. Do not
   substitute missing inputs with zeros. Do not promote a model if mappings
   remain unverified. Container coverage is a domain difference to document.
3. Preserve the existing native blocked partition and current model settings.
   Any external recordings used for fitting must belong to the official training
   partition and be normal. Fit transformations on training inputs only.
4. Compare native-only and augmented models at the same baseline-validation FPR
   target. Select augmentation on validation only. A candidate must strictly
   reduce native validation false positives, maintain native validation recall
   overall and in every attack phase, and retain at least 95% recall per phase.
   Report external normal false alarms separately; pool neither source's metrics
   to conceal regressions on native desktop workloads.
5. Freeze candidate selection before evaluating the reserved native blocks and
   external official test recordings. Promotion additionally requires fewer
   native-test false positives, no reduction in overall or per-phase native-test
   recall, and no external-test false-alarm regression versus native-only.
   If no candidate passes, keep the current model; do not retune on test results.
6. Never call the native blocks new independent data: both native sessions have
   already been examined. A single external server scenario would establish
   only preliminary evidence, not general desktop or malware protection.

The deployed bundle is preserved at
`models/output/improved/detector_bundle.joblib`; experimental outputs must use a
separate directory. An inability to obtain data or pass compatibility is an
incomplete test, not evidence that the dataset is bad or beneficial.
