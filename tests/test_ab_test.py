"""The threshold A/B test: paired flags, the McNemar test and the table in the README."""

from pathlib import Path

import pytest
from scipy.stats import binomtest

from bank import ab_test


def test_mcnemar_matches_an_exact_binomial_test():
    assert ab_test.mcnemar_p(0, 0) == 1.0
    assert ab_test.mcnemar_p(5, 5) == 1.0
    assert ab_test.mcnemar_p(0, 11) == pytest.approx(2 / 2**11)
    assert ab_test.mcnemar_p(3, 14) == ab_test.mcnemar_p(14, 3)
    assert ab_test.mcnemar_p(3, 14) == pytest.approx(binomtest(3, 17).pvalue)


def test_lower_threshold_flags_everything_the_higher_one_does():
    data = ab_test.traffic()
    strict = ab_test.flags(data, 2.0)
    sensitive = ab_test.flags(data, 1.5)
    assert sensitive.sum() > strict.sum()
    assert not (strict & ~sensitive).any()


def test_readme_shows_the_ab_test():
    readme = (Path(__file__).parent.parent / "README.md").read_text()
    assert ab_test.report() in readme
