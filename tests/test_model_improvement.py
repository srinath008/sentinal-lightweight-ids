import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest, ExtraTreesClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer
from feature_engineering.events import FEATURES, Window
from feature_engineering.model_features import behavioural_features
from inference.detector import Detector
from models.improve_existing import blocked_split, normal_scores, selection_key


def test_blocked_split_has_embargo_and_both_normal_profiles():
    rows = []
    for sid in ('idle', 'media'):
        for phase, offset in [('baseline', 0), ('attack_recon', 100)]:
            rows.extend(dict(session_id=sid, phase=phase, window_index=offset + i) for i in range(80))
    parts, manifest = blocked_split(pd.DataFrame(rows))
    for part in parts.values():
        assert set(part.session_id) == {'idle', 'media'}
    for sid in ('idle', 'media'):
        train = parts['train'].query('session_id == @sid and phase == "baseline"')
        valid = parts['validation'].query('session_id == @sid and phase == "baseline"')
        test = parts['test'].query('session_id == @sid and phase == "baseline"')
        assert valid.window_index.min() - train.window_index.max() == 5
        assert test.window_index.min() - valid.window_index.max() == 5
    assert sum(item['count'] for item in manifest) == sum(map(len, parts.values()))


def test_derived_features_handle_idle_and_large_counts():
    values = np.array([[0, 0, 0, 0, 0, 0, 0], [100, 5, np.log1p(10000), np.log1p(50), 10, 200, 2]])
    transformed = behavioural_features(values)
    assert transformed.shape == (2, 11)
    assert np.isfinite(transformed).all()
    np.testing.assert_allclose(transformed[1, 7], 10 / 10001)


def test_selection_prefers_qualifying_unsupervised_over_known_scenario_classifier():
    def record(family, recall):
        return dict(family=family, artifact_bytes=100,
                    validation=dict(per_phase={'baseline': 0, 'attack_recon': recall},
                                    baseline_false_positive_rate=0, f1=recall))
    assert selection_key(record('unsupervised', .96)) > selection_key(record('supervised_known_simulations', 1.))
    assert selection_key(record('supervised_known_simulations', 1.)) > selection_key(record('unsupervised', .8))


def test_selected_bundle_matches_training_scores_for_both_families(tmp_path):
    rng = np.random.default_rng(42)
    values = rng.poisson(3, size=(80, 7)).astype(float)
    for family in ('unsupervised', 'supervised_known_simulations'):
        if family == 'unsupervised':
            model = make_pipeline(FunctionTransformer(behavioural_features), IsolationForest(n_estimators=20, random_state=42)).fit(values)
        else:
            model = make_pipeline(FunctionTransformer(behavioural_features), ExtraTreesClassifier(n_estimators=20, random_state=42)).fit(values, np.arange(80) % 2)
        threshold = float(np.median(normal_scores(model, family, values)))
        path = tmp_path / f'{family}.joblib'
        joblib.dump(dict(schema_version=2, features=FEATURES, window_seconds=5,
                         window_origin='first_valid_event_across_sources', sklearn_version=sklearn.__version__,
                         format='selected_pipeline_v1', family=family, pipeline=model,
                         primary_name='selected', threshold=threshold), path)
        detector = Detector(path)
        row = Window().row('session', 0, 100, 5)
        row.update(zip(FEATURES, values[0]))
        expected = float(normal_scores(model, family, values[:1])[0])
        scored = detector.score(row)
        assert scored['scores']['selected'] == expected
        assert scored['anomaly'] == (expected < threshold)


def test_incident_grouping_resets_at_omitted_test_blocks():
    from models.incident_metrics import incident_metrics
    frame = pd.DataFrame(dict(session_id=['s'] * 4, window_index=[0, 1, 100, 101],
                             window_start=[0, 5, 500, 505],
                             phase=['baseline', 'baseline', 'attack_recon', 'attack_recon']))
    result = incident_metrics(frame, np.array([-2., -2., -2., -2.]), -1, 5)
    assert result['incident_starts'] == 2
    assert result['scenarios'][0]['incident_active_at_phase_start'] is False
    assert result['scenarios'][0]['detection_delay_seconds'] == 10
