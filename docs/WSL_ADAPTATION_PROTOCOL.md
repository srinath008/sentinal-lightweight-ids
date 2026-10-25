# WSL adaptation protocol — 2026-10-17

The user authorized host adaptation, model comparisons and safe performance
improvements. Original datasets and the selected historical model are preserved.

## Collection

`experiments/collect_wsl_adaptation.py` collects aggregate feature rows only;
command arguments, file contents, paths and process identifiers are not saved.
The privileged collector traces Linux activity. Synthetic workloads run as the
ordinary Ubuntu user, create temporary synthetic files and connect only to a
temporary loopback listener. No external scanning or malicious executable runs.
Windows browsing/media/Excel activity is background load, not labelled Linux
browsing. The collector and generated tasks run at reduced priority.

The fixed plan contains six 120-second sessions: idle and benign synthetic
file/process/network activity for training, then validation, then final test.
Three subsequent 60-second test probes generate bounded local TCP, execution
and file/error bursts. These are unusual benign workloads, not malware labels.
Two windows at each session edge are excluded to avoid tracer/workload startup.
All sessions must finish without malformed or late rows and without collector
stderr. Incomplete data cannot be used for selection.

The native dashboard remains open to include its own activity. No process name,
loopback range or application is broadly whitelisted. The HTTP connection-reuse
change is tested separately after collection so app versions do not change
between the fixed collection partitions.

## Training and selection

`models/adapt_wsl.py` compares SVM kernels/regularization, Isolation Forest,
Local Outlier Factor, Extra Trees and histogram gradient boosting. Training is
limited to two CPU threads. Native historical chronological train/validation/
test blocks retain their original embargo; WSL sessions stay disjoint. WSL
training rows may be repeated to balance host domains, entirely inside training.
Unsupervised models see baseline training rows only. Supervised models also see
historical known scripted simulations; this restricts the claims they support.

Cutoffs use validation only. Candidates must achieve at least 95% recall for
each historical validation attack phase, at most 2% historical baseline flags,
and at most 5% flags in each WSL validation normal profile. Selection is frozen
to disk before test scores are evaluated. The ranking prefers the highest
worst historical phase recall minus worst WSL normal flag rate, then fewer
normal flags, then an unsupervised model, then a smaller artifact.

Final gates require validation to pass, at least 95% recall in each historical
test attack phase, at most 3% historical baseline flags, at most 5% flags in each
WSL test normal profile, and at least 80% flags in each harmless stress probe.
Passing these gates only supports an experimental local preview. It does not
establish general malware detection, performance on another host, or a reliable
population false-positive rate from these small samples. An earlier unlabeled
51-window user session is an additional audit, never a training/selection input.

The experiment writes a separate candidate artifact and report. Installing any
candidate additionally requires working Ubuntu inference and validation after
the app's connection-reuse change, with the original model retained for rollback.
The on-demand ClamAV scanner and its official signatures remain independent.

## Adaptive follow-up after first-round rejection

The first selected gradient-boosting model passed historical and normal-workload
checks but missed most TCP stress windows and all file stress windows. It was
not installed. A fresh second collection round uses 90-second normal sessions
and 60-second stress sessions after the HTTP connection-reuse improvement.
Its candidate set is restricted to normal-only novelty detectors. Earlier
train/validation partitions may be reused, but their test rows are excluded.
Session identifiers include the capture-directory name to prevent collisions.

For this explicitly adaptive development round, additional older baseline
examples may be fitted: the first 25 earlier user windows (assumed normal, not
verified ground truth) and earlier requested-idle diagnostics that included
automatic updates. This revises the first round's no-earlier-report-training
rule, and is disclosed rather than treating those records as unseen validation.
The later 26 user windows remain only a retrospective audit. Final second-round
normal and stress sessions are excluded from fitting, calibration and selection.
No claim of a wholly untouched global historical test set is made after these
repeated development rounds. The independent gate evidence is limited to the
fresh follow-up workload sessions on this host.

Before evaluating second-round test scores, three normal-profile union
candidates were added. Each combines the frozen reference normal SVM with a
local normal-only SVM; a window is flagged only if both consider it unusual.
Their relative-normality cutoff is capped at one, so a window accepted by the
reference remains accepted. Among candidates passing every validation gate,
the follow-up ranking prefers this preserved reference-normal acceptance before
ranking recall/false-alert tradeoffs. These changes are adaptive development
choices prompted by the first round; no second-round test scores informed them.

## Third-round correction of normal workload coverage

Round two preserved historical results and flagged all three stress probes,
but flagged two of thirteen benign test windows. Those windows included ordinary
system-command activity (12–20 executions and 6–13 distinct commands), which the
simple `true`/file/TCP normal workload had underrepresented. No model was deployed.
The benign generator now also uses bounded read-only `uname`, `date`, `id`, `df`
and `ps` calls. A fresh third round uses 90-second normal sessions and 45-second
stress sessions. Earlier normal test rows can explicitly become development
training, excluding stress rows; their earlier held-out status is not claimed
for this new round. Final third-round sessions remain separate. Qualified model
ranking also breaks worst-profile false-rate ties using mean profile false rate
before model size, so a smaller model cannot win by having more validation flags.
The third round also tightens the local validation calibration target to 1%
(with these sample sizes, the minimum normal score). Historical attack-recall
gates remain unchanged; a quieter cutoff that loses detection is still rejected.
