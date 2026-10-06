"""Monte Carlo accuracy tests: repeatable, correct at the edges, and close to the exact formula."""
import numpy as np
import pytest

from risk import monte_carlo
from risk.risk_calculator import load_register


def new_generator(seed=1):
    return np.random.default_rng(seed)


def test_same_seed_gives_identical_results():
    first = monte_carlo.simulate(0.4, 450000, 1.1, 5000, new_generator(7))
    second = monte_carlo.simulate(0.4, 450000, 1.1, 5000, new_generator(7))

    assert np.array_equal(first, second)


def test_zero_event_rate_means_zero_loss():
    losses = monte_carlo.simulate(0.0, 450000, 1.1, 1000, new_generator())

    assert losses.sum() == 0


def test_with_no_spread_every_event_loses_exactly_the_median():
    losses = monte_carlo.simulate(2.0, 1000, 0.0, 20000, new_generator())    # sigma 0 means no spread

    in_thousands = losses / 1000
    assert np.allclose(in_thousands, np.round(in_thousands))                 # always a whole number of events
    assert losses.mean() == pytest.approx(2.0 * 1000, rel=0.03)


@pytest.mark.parametrize("event_rate,median_loss,sigma", [(0.4, 450000, 1.1), (0.25, 250000, 1.0), (1.5, 1000, 0.5)])
def test_simulated_average_matches_the_exact_formula(event_rate, median_loss, sigma):
    losses = monte_carlo.simulate(event_rate, median_loss, sigma, 300000, new_generator(3))

    exact_average = monte_carlo.expected_loss(event_rate, median_loss, sigma)
    assert losses.mean() == pytest.approx(exact_average, rel=0.03)


def test_percentiles_and_threshold_probability_behave():
    losses = monte_carlo.simulate(0.4, 450000, 1.1, 50000, new_generator())

    summary_low_threshold = monte_carlo.summarize(losses, 100000)
    summary_high_threshold = monte_carlo.summarize(losses, 1000000)

    assert summary_low_threshold["p90"] >= summary_low_threshold["p50"] >= 0
    assert 0 <= summary_high_threshold["prob_exceed_threshold"] <= 1
    assert summary_high_threshold["prob_exceed_threshold"] <= summary_low_threshold["prob_exceed_threshold"]


@pytest.mark.parametrize("bad_arguments", [(-1, 1, 1, 10), (1, -1, 1, 10), (1, 1, -1, 10), (1, 1, 1, 0)])
def test_invalid_inputs_are_rejected(bad_arguments):
    with pytest.raises(ValueError):
        monte_carlo.simulate(*bad_arguments, new_generator())


@pytest.fixture(scope="module")
def results():
    return monte_carlo.run(load_register(), trials=100000, seed=11)


def test_selection_is_the_highest_inherent_risks(results):
    assert len(results["risks"]) == 6
    assert results["risks"][0]["risk_id"] == "RISK-REMOTE-ACCESS-01"
    assert results["risks"][0]["inherent_risk"] == 25


def test_remediation_reduces_expected_loss_only_for_closed_risks(results):
    for risk in results["risks"]:
        if risk["retest_status"] == "PASS":
            assert risk["after"]["expected_loss"] < risk["before"]["expected_loss"]
        else:
            assert risk["event_rate_after"] == risk["event_rate_before"]


def test_portfolio_is_the_sum_of_its_risks_and_improves(results):
    portfolio = results["portfolio"]

    sum_of_risks = 0
    for risk in results["risks"]:
        sum_of_risks = sum_of_risks + risk["before"]["expected_loss"]

    assert portfolio["before"]["expected_loss"] == pytest.approx(sum_of_risks, rel=0.001)
    assert portfolio["after"]["expected_loss"] < portfolio["before"]["expected_loss"]
    assert portfolio["after"]["prob_exceed_threshold"] <= portfolio["before"]["prob_exceed_threshold"]


def test_each_simulated_risk_is_close_to_its_exact_value(results):
    for risk in results["risks"]:
        assert risk["before"]["expected_loss"] == pytest.approx(risk["analytic_expected_loss_before"], rel=0.05)
