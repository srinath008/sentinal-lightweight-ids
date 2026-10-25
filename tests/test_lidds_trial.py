import pandas as pd
from models.lidds_trial import evaluate, passes


def result(fp=4, recall=1., phase=1.):
    return dict(false_positives=fp, recall=recall, per_phase={'attack_recon':phase})


def test_gate_requires_false_alarm_improvement_without_detection_regression():
    assert passes(result(), result(fp=3))
    assert not passes(result(), result())
    assert not passes(result(), result(fp=3, recall=.99))
    assert not passes(result(), result(fp=3, phase=.94))


def test_normal_only_external_validation_has_no_attack_recall():
    frame = pd.DataFrame({'phase':['baseline','baseline']})
    values = evaluate(frame, [0.,1.], .5)
    assert values['false_positives'] == 1
    assert values['recall'] is None
    assert values['f1'] is None
