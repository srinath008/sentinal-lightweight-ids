"""Compare detectors with chronological blocks from both existing sessions.

This is an exploratory within-dataset experiment, not independent-session
validation. Historically these data have already been examined. Test blocks
are excluded from selection within this run, not claimed never-before-seen.
"""
import argparse
import hashlib
import json
import time
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest, ExtraTreesClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import LocalOutlierFactor
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler
from sklearn.svm import OneClassSVM
from feature_engineering.events import FEATURES, SCHEMA_VERSION
from feature_engineering.model_features import behavioural_features
from models.validated_training import calibrate, metrics
from models.incident_metrics import incident_metrics


def blocked_split(frame, embargo=2):
    """First 50% training, next 25% validation, final 25% test per phase/session.

    Remove two windows on each side of internal split boundaries. Mixed phase
    edges (first/last two windows) are removed to limit transition ambiguity.
    """
    pieces = {name: [] for name in ('train', 'validation', 'test')}
    manifest = []
    for (sid, phase), block in frame.groupby(['session_id', 'phase'], sort=True):
        if phase != 'baseline' and not phase.startswith('attack_'):
            continue
        block = block.sort_values('window_index')
        n = len(block)
        a, b = int(n * .5), int(n * .75)
        slices = {'train': (embargo, a - embargo),
                  'validation': (a + embargo, b - embargo),
                  'test': (b + embargo, n - embargo)}
        for name, (start, end) in slices.items():
            if end <= start:
                raise ValueError('Not enough windows for blocked evaluation')
            part = block.iloc[start:end].copy()
            pieces[name].append(part)
            manifest.append(dict(partition=name, session_id=sid, phase=phase, count=len(part),
                                 first_window=int(part.window_index.min()), last_window=int(part.window_index.max())))
    result = {name: pd.concat(parts).sort_values(['session_id', 'window_index']).reset_index(drop=True)
              for name, parts in pieces.items()}
    keys = [set(zip(part.session_id, part.window_index)) for part in result.values()]
    if any(keys[i] & keys[j] for i in range(3) for j in range(i)):
        raise ValueError('Partition overlap')
    return result, manifest


def candidates():
    for trees in (100, 200):
        for samples in (128, 256):
            yield f'if_log_{trees}_{samples}', 'unsupervised', make_pipeline(
                FunctionTransformer(behavioural_features),
                IsolationForest(n_estimators=trees, max_samples=samples, random_state=42, n_jobs=-1))
    yield 'if_original_features', 'unsupervised', IsolationForest(n_estimators=200, random_state=42, n_jobs=-1)
    for gamma in (.01, .1, 1.):
        for nu in (.02, .05):
            yield f'ocsvm_log_g{gamma}_nu{nu}', 'unsupervised', make_pipeline(
                FunctionTransformer(behavioural_features), StandardScaler(), OneClassSVM(gamma=gamma, nu=nu))
    for neighbors in (10, 20, 40):
        yield f'lof_log_k{neighbors}', 'unsupervised', make_pipeline(
            FunctionTransformer(behavioural_features), StandardScaler(),
            LocalOutlierFactor(n_neighbors=neighbors, novelty=True))
    # Labelled simulations are available; compare explicit supervised models.
    # Their evidence only covers these known scripted scenarios.
    for leaf in (2, 5, 10):
        yield f'extratrees_leaf{leaf}', 'supervised_known_simulations', make_pipeline(
            FunctionTransformer(behavioural_features),
            ExtraTreesClassifier(n_estimators=200, min_samples_leaf=leaf,
                                 class_weight='balanced', random_state=42, n_jobs=-1))
    yield 'randomforest_leaf5', 'supervised_known_simulations', make_pipeline(
        FunctionTransformer(behavioural_features),
        RandomForestClassifier(n_estimators=200, min_samples_leaf=5,
                               class_weight='balanced', random_state=42, n_jobs=-1))
    yield 'logistic', 'supervised_known_simulations', make_pipeline(
        FunctionTransformer(behavioural_features), StandardScaler(),
        LogisticRegression(class_weight='balanced', max_iter=2000, random_state=42))


def normal_scores(model, family, values):
    if family == 'supervised_known_simulations':
        index = int(np.flatnonzero(model.classes_ == 0)[0])
        return model.predict_proba(values)[:, index]
    return model.score_samples(values)


def selection_key(record):
    validation = record['validation']
    phases = [value for key, value in validation['per_phase'].items() if key.startswith('attack_')]
    # Predeclared preference: meet >=95% recall in EACH known phase at <=1%
    # validation FPR, then prefer baseline-only learning and smaller models.
    qualifies = min(phases) >= .95 and validation['baseline_false_positive_rate'] <= .01
    return (qualifies, record['family'] == 'unsupervised' if qualifies else False,
            min(phases), validation['f1'], -record['artifact_bytes'])


def run(args):
    meta = json.loads(args.features.with_suffix('.metadata.json').read_text())
    if meta['schema_version'] != SCHEMA_VERSION or meta['window_seconds'] != 5:
        raise ValueError('Use corrected five-second feature table')
    frame = pd.read_parquet(args.features)
    pieces, split_manifest = blocked_split(frame)
    training, valid, test = (pieces[name] for name in ('train', 'validation', 'test'))
    vectors = {name: part[FEATURES].to_numpy(dtype=float) for name, part in pieces.items()}
    baseline_train = training.phase.eq('baseline').to_numpy()
    baseline_valid = valid.phase.eq('baseline').to_numpy()
    labels = training.phase.str.startswith('attack_').to_numpy(dtype=int)
    args.output.mkdir(parents=True, exist_ok=True)
    import io
    trained, records = {}, []
    for name, family, model in candidates():
        begin = time.perf_counter()
        if family == 'unsupervised':
            model.fit(vectors['train'][baseline_train])
        else:
            model.fit(vectors['train'], labels)
        scores = normal_scores(model, family, vectors['validation'])
        threshold = calibrate(scores[baseline_valid], .01)
        buffer = io.BytesIO()
        joblib.dump(model, buffer)
        record = dict(name=name, family=family, threshold=threshold,
                      artifact_bytes=buffer.tell(), training_seconds=time.perf_counter() - begin,
                      validation=metrics(valid, scores, threshold, 5))
        records.append(record)
        trained[name] = model
        print(f"{name}: validation FPR={record['validation']['baseline_false_positive_rate']:.3f} recall={record['validation']['recall']:.3f}", flush=True)
    # Freeze selection BEFORE accessing test feature vectors through a model.
    selected = max(records, key=selection_key)
    (args.output / 'selection_before_test.json').write_text(json.dumps(dict(
        selected=selected, split_manifest=split_manifest, candidates=records), indent=2))
    model = trained[selected['name']]
    test_scores = normal_scores(model, selected['family'], vectors['test'])
    test_result = metrics(test, test_scores, selected['threshold'], 5)
    per_session = {}
    for sid in test.session_id.unique():
        mask = test.session_id.eq(sid).to_numpy()
        per_session[sid] = metrics(test[mask], test_scores[mask], selected['threshold'], 5)
    # Fair reference: same training blocks from both profiles, default IF cutoff.
    reference = IsolationForest(n_estimators=200, random_state=42, n_jobs=-1).fit(vectors['train'][baseline_train])
    reference_test = reference.score_samples(vectors['test'])
    bundle = dict(schema_version=SCHEMA_VERSION, features=FEATURES, window_seconds=5.,
                  window_origin=meta['window_origin'], sklearn_version=sklearn.__version__,
                  format='selected_pipeline_v1', primary_name=selected['name'],
                  family=selected['family'], pipeline=model, threshold=selected['threshold'],
                  evaluation_scope='chronological blocks within two previously examined sessions',
                  transformations='behavioural_features in feature_engineering.model_features; fitted pipeline persisted')
    path = args.output / 'detector_bundle.joblib'
    joblib.dump(bundle, path)
    report = dict(dataset_sha256=hashlib.sha256(args.features.read_bytes()).hexdigest(),
                  protocol='50/25/25 chronological split per phase/session; 2-window embargo at boundaries; selection uses validation only',
                  limitation='Same two previously examined sessions; no independent new session, machine, or malware validation. Test blocks are reserved for this run only.',
                  selection_rule='Meet >=95% recall for every validation attack phase at <=1% validation baseline FPR; prefer unsupervised if qualifying; then worst-phase recall, F1, model size.',
                  split_manifest=split_manifest, candidates=records, selected=selected,
                  test=test_result, test_per_session=per_session,
                  test_incidents=incident_metrics(test, test_scores, selected['threshold'], 5),
                  incident_metric_scope='Rates extrapolated from retained test-block duration; gaps reset incident state. Attack delays refer to retained fragments, not actual attack onsets.',
                  fair_reference_default_if_test=metrics(test, reference_test, -.5, 5),
                  artifact=dict(path=str(path), bytes=path.stat().st_size,
                                sha256=hashlib.sha256(path.read_bytes()).hexdigest(), sklearn_version=sklearn.__version__))
    args.report.write_text(json.dumps(report, indent=2))
    scored = test[['session_id', 'window_index', 'window_start', 'phase']].copy()
    scored['normal_score'], scored['anomaly'] = test_scores, test_scores < selected['threshold']
    scored.to_parquet(args.output / 'reserved_test_scores.parquet', index=False)
    print(json.dumps(dict(selected=selected['name'], family=selected['family'], test=test_result, reference=report['fair_reference_default_if_test']), indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--features', type=Path, default=Path('feature_engineering/output/features_window5s_v2.parquet'))
    parser.add_argument('--output', type=Path, default=Path('models/output/improved'))
    parser.add_argument('--report', type=Path, default=Path('docs/MODEL_IMPROVEMENT_RESULTS.json'))
    run(parser.parse_args())


if __name__ == '__main__':
    main()
