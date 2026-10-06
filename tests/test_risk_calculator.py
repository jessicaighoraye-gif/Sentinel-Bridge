"""Accuracy tests for the risk formulas."""
import pytest

from risk import risk_calculator


@pytest.mark.parametrize("likelihood,impact,expected", [(1, 1, 1), (5, 5, 25), (4, 5, 20), (2, 3, 6)])
def test_inherent_risk_is_likelihood_times_impact(likelihood, impact, expected):
    assert risk_calculator.inherent_score(likelihood, impact) == expected


@pytest.mark.parametrize("likelihood,impact", [(0, 3), (6, 3), (3, 0), (3, 6), (2.5, 3), (True, 3), ("3", 3)])
def test_invalid_scale_values_are_rejected(likelihood, impact):
    with pytest.raises(ValueError):
        risk_calculator.inherent_score(likelihood, impact)


@pytest.mark.parametrize("score,band", [(1, "Low"), (4, "Low"), (5, "Medium"), (9, "Medium"), (10, "High"),
                                        (16, "High"), (17, "Critical"), (25, "Critical")])
def test_rating_band_boundaries(score, band):
    assert risk_calculator.rating(score) == band


@pytest.mark.parametrize("bad_score", [0, 26, -3])
def test_rating_rejects_scores_outside_the_scale(bad_score):
    with pytest.raises(ValueError):
        risk_calculator.rating(bad_score)


def test_residual_risk_formula():
    assert risk_calculator.residual_score(20, 0.0) == 20
    assert risk_calculator.residual_score(20, 0.9) == 2.0
    assert risk_calculator.residual_score(20, 1.0) == 0


@pytest.mark.parametrize("bad_effectiveness", [-0.1, 1.5])
def test_residual_risk_rejects_effectiveness_outside_zero_to_one(bad_effectiveness):
    with pytest.raises(ValueError):
        risk_calculator.residual_score(20, bad_effectiveness)


def test_impact_comes_from_asset_criticality():
    assert risk_calculator.impact_for("low") == 2
    assert risk_calculator.impact_for("critical") == 5
