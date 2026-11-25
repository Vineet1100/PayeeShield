"""The detector comparison: test set, metrics and the table published in the README."""

from pathlib import Path

import numpy as np

from bank import evaluation


def test_test_set_has_every_pattern_labelled():
    data = evaluation.labelled_purchases()
    labels, counts = np.unique(data["label"], return_counts=True)
    expected = {"normal": evaluation.NORMAL_COUNT}
    expected.update({p: evaluation.PER_PATTERN for p in evaluation.PATTERNS})
    assert dict(zip(labels, counts, strict=True)) == expected
    card_testing = data["label"] == "card testing"
    assert data["online"][card_testing].all() and (data["amount"][card_testing] < 3).all()
    assert (data["hour"][data["label"] == "night-time"] < 6).all()


def test_metrics():
    flagged = np.array([True, True, False, False, True])
    is_fraud = np.array([True, False, True, False, False])
    assert evaluation.metrics(flagged, is_fraud) == {
        "precision": 1 / 3,
        "recall": 1 / 2,
        "false_positive_rate": 2 / 3,
    }
    assert evaluation.metrics(np.zeros(2, bool), np.zeros(2, bool))["precision"] == 0.0


def test_readme_table_matches_the_evaluation():
    readme = (Path(__file__).parent.parent / "README.md").read_text()
    assert evaluation.report() in readme
