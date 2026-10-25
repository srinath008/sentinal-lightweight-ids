import json
import numpy as np
import pandas as pd
import pytest
from feature_engineering.events import FEATURES
from models.adapt_wsl import read_sessions, qualifies, selection_key, wsl_metrics


def test_host_sessions_keep_partitions_disjoint_and_remove_edges(tmp_path):
    sessions=[]
    for part in ('train','validation','test'):
        sid='wsl_'+part
        rows=[dict(session_id=sid,partition=part,workload='idle',phase='baseline',
                   window_index=i,**{key:0 for key in FEATURES}) for i in range(10)]
        (tmp_path/(sid+'.json')).write_text(json.dumps(rows))
        sessions.append(dict(session_id=sid))
    manifest=dict(status='complete',sessions=sessions)
    (tmp_path/'manifest.json').write_text(json.dumps(manifest))
    parts,_=read_sessions(tmp_path)
    for part in parts:
        assert parts[part].window_index.tolist()==list(range(2,8))
        assert parts[part].session_id.unique().tolist()==[tmp_path.name+':wsl_'+part]
    manifest['status']='incomplete'
    (tmp_path/'manifest.json').write_text(json.dumps(manifest))
    with pytest.raises(ValueError,match='finish'):
        read_sessions(tmp_path)


def test_validation_gate_rejects_quiet_model_that_misses_attacks():
    good=dict(family='unsupervised',artifact_bytes=100,
        historical_validation=dict(per_phase={'attack_recon':.98,'attack_fileaccess':1.},baseline_false_positive_rate=.01),
        wsl_validation={'idle':{'flagged_fraction':0},'benign':{'flagged_fraction':0}})
    bad=dict(good,historical_validation=dict(per_phase={'attack_recon':.99,'attack_fileaccess':0},baseline_false_positive_rate=0))
    assert qualifies(good)
    assert not qualifies(bad)
    assert selection_key(good)>selection_key(bad)


def test_normal_profiles_are_not_pooled_to_hide_bad_performance():
    frame=pd.DataFrame({'workload':['idle']*20+['benign']*2})
    result=wsl_metrics(frame,np.array([1.]*20+[0.]*2),.5)
    assert result['idle']['flagged_fraction']==0
    assert result['benign']['flagged_fraction']==1


def test_profile_union_preserves_reference_normal_windows():
    from inference.profile_union import NormalProfileUnion
    class Fixed:
        def __init__(self, scores):self.scores=np.array(scores)
        def score_samples(self, values):return self.scores
    model=NormalProfileUnion(Fixed([2.,.2,.2]),1.,None,None)
    model.reference_scale_=1.
    model.host_threshold_=1.
    model.host_pipeline_=Fixed([0.,2.,0.])
    scores=model.score_samples(np.zeros((3,7)))
    assert (scores<1.).tolist()==[False,False,True]


def test_profile_union_scaler_uses_training_only_and_survives_save(tmp_path):
    import joblib
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import FunctionTransformer, StandardScaler
    from sklearn.svm import OneClassSVM
    from feature_engineering.model_features import behavioural_features
    from inference.profile_union import NormalProfileUnion
    rng=np.random.default_rng(42)
    training=rng.poisson(3,size=(50,7)).astype(float)
    validation=np.full((10,7),10.)
    reference=make_pipeline(FunctionTransformer(behavioural_features),StandardScaler(),OneClassSVM()).fit(training)
    model=NormalProfileUnion(reference,.1,training,validation).fit(training)
    np.testing.assert_allclose(model.host_pipeline_.named_steps['standardscaler'].mean_,
                               behavioural_features(training).mean(axis=0))
    path=tmp_path/'union.joblib'
    joblib.dump(model,path)
    loaded=joblib.load(path)
    np.testing.assert_allclose(loaded.score_samples(training),model.score_samples(training))
