"""Accept either historical or local normality without whitelisting events."""
import numpy as np
from sklearn.base import BaseEstimator
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler
from sklearn.svm import OneClassSVM
from feature_engineering.model_features import behavioural_features


class NormalProfileUnion(BaseEstimator):
    """Two normal-only SVMs; an event window is unusual to both to be flagged.

    Scores are relative normality, not probabilities. Calibration arrays are
    used only for cutoffs, never for fitted model/scaler coefficients.
    """
    def __init__(self, reference_pipeline, reference_threshold, host_training,
                 host_validation, gamma=.1, nu=.01, target_fpr=.05):
        self.reference_pipeline=reference_pipeline
        self.reference_threshold=reference_threshold
        self.host_training=host_training
        self.host_validation=host_validation
        self.gamma=gamma
        self.nu=nu
        self.target_fpr=target_fpr

    def fit(self, unused_native_training, y=None):
        self.host_pipeline_=make_pipeline(FunctionTransformer(behavioural_features),StandardScaler(),
                                         OneClassSVM(gamma=self.gamma,nu=self.nu))
        self.host_pipeline_.fit(self.host_training)
        scores=np.sort(self.host_pipeline_.score_samples(self.host_validation))
        if not len(scores) or not np.isfinite(scores).all():raise ValueError('Invalid host calibration')
        if not 0<=self.target_fpr<1:raise ValueError('Invalid host false-alert target')
        self.host_threshold_=max(float(scores[int(np.floor(self.target_fpr*len(scores)))]),1e-12)
        self.reference_scale_=max(float(self.reference_threshold),1e-12)
        return self

    def score_samples(self, values):
        historical=self.reference_pipeline.score_samples(values)/self.reference_scale_
        local=self.host_pipeline_.score_samples(values)/self.host_threshold_
        return np.maximum(historical,local)
