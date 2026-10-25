"""Load validated model settings and group window predictions into incidents."""
import math
import joblib
import numpy as np
import sklearn
from feature_engineering.events import FEATURES, SCHEMA_VERSION


class Detector:
    def __init__(self, path):
        # Only load trusted project artifacts: joblib uses pickle internally.
        self.bundle = joblib.load(path)
        if self.bundle.get('schema_version') != SCHEMA_VERSION or self.bundle.get('features') != FEATURES:
            raise ValueError('Incompatible model schema; retrain using validated_training')
        if self.bundle.get('window_origin') != 'first_valid_event_across_sources':
            raise ValueError('Unsupported window-origin policy')
        if self.bundle.get('format') == 'selected_pipeline_v1':
            if not math.isfinite(self.bundle['threshold']):
                raise ValueError('Invalid anomaly threshold')
            if self.bundle['family'] not in ('unsupervised', 'supervised_known_simulations'):
                raise ValueError('Unsupported model family')
        else:
            for name in ('isolation_forest', 'ocsvm'):
                if not math.isfinite(self.bundle['thresholds'][name]):
                    raise ValueError('Invalid anomaly threshold')
        if self.bundle['sklearn_version'] != sklearn.__version__:
            raise ValueError('Use the same scikit-learn version as model training')
        self.seconds = self.bundle['window_seconds']
        if not math.isfinite(self.seconds) or self.seconds <= 0:
            raise ValueError('Invalid model window duration')

    def score(self, row):
        vector = np.asarray([[row[key] for key in FEATURES]], dtype=float)
        if not np.isfinite(vector).all():
            raise ValueError('Non-finite features')
        if self.bundle.get('format') == 'selected_pipeline_v1':
            model = self.bundle['pipeline']
            if self.bundle['family'] == 'supervised_known_simulations':
                normal_index = int(np.flatnonzero(model.classes_ == 0)[0])
                score = float(model.predict_proba(vector)[0, normal_index])
            else:
                score = float(model.score_samples(vector)[0])
            name = self.bundle['primary_name']
            anomalous = score < self.bundle['threshold']
            return dict(row, scores={name: score}, anomalies={name: anomalous}, anomaly=anomalous)
        scores = dict(isolation_forest=float(self.bundle['models']['isolation_forest'].score_samples(vector)[0]),
                      ocsvm=float(self.bundle['models']['ocsvm'].decision_function(self.bundle['scaler'].transform(vector))[0]))
        anomalies = {name: score < self.bundle['thresholds'][name] for name, score in scores.items()}
        return dict(row, scores=scores, anomalies=anomalies, anomaly=anomalies['isolation_forest'])


class IncidentGrouper:
    """One incident per run; report suppressed starts during a cooldown."""
    def __init__(self, consecutive=2, cooldown=60):
        if consecutive < 1 or not math.isfinite(cooldown) or cooldown < 0:
            raise ValueError('Invalid incident policy')
        self.consecutive, self.cooldown = consecutive, cooldown
        self.run = self.clean = 0
        self.active = False
        self.last_notification = float('-inf')
        self.start = None

    def update(self, row):
        stamp = row['window_start']
        if row['anomaly']:
            if self.run == 0:
                self.start = stamp
            self.run += 1
            self.clean = 0
            if self.run >= self.consecutive and not self.active:
                self.active = True
                notify = stamp - self.last_notification >= self.cooldown
                if notify:
                    self.last_notification = stamp
                return dict(type='incident_start', window_start=stamp,
                            first_anomalous_window=self.start, notification=notify,
                            scores=row['scores'], features={key: row[key] for key in FEATURES})
        else:
            self.run = 0
            self.clean += 1
            if self.active and self.clean >= self.consecutive:
                self.active = False
                return dict(type='incident_end', window_start=stamp)
        return None
