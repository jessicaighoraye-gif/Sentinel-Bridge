"""Monte Carlo layer: how uncertain is the yearly loss from the biggest risks?

This is an advanced analysis on top of the normal risk register. It does not replace it.

The model, for each risk:
  * the number of loss events in a year is random (Poisson, at the risk's yearly event rate)
  * the size of each loss is random (lognormal, around the risk's median loss)
After remediation, a risk whose retest passed has its event rate reduced by the
control's effectiveness.

A check for the maths: the average yearly loss should be close to
    event rate x median loss x exp(sigma squared / 2)
"""
import json
import math
from pathlib import Path

import numpy as np

from risk.risk_calculator import ROOT, load_parameters


def expected_loss(event_rate, median_loss, sigma):
    """The exact average yearly loss for one risk, from the formula above."""
    return event_rate * median_loss * math.exp(sigma ** 2 / 2)


def simulate(event_rate, median_loss, sigma, trials, random_generator):
    """Simulate the loss of one risk over many pretend years. Returns one number per year."""
    if event_rate < 0 or median_loss < 0 or sigma < 0 or trials < 1:
        raise ValueError("rate, median and sigma must be non-negative and trials at least 1")

    # How many loss events happen in each pretend year.
    events_per_year = random_generator.poisson(event_rate, trials)
    total_events = int(events_per_year.sum())

    # How big each loss event is.
    if total_events > 0:
        if median_loss > 0:
            log_of_median = math.log(median_loss)
        else:
            log_of_median = 0.0
        loss_of_each_event = random_generator.lognormal(log_of_median, sigma, total_events)
    else:
        loss_of_each_event = np.array([])
    if median_loss == 0:
        loss_of_each_event = np.zeros_like(loss_of_each_event)

    # Add up the events of each year.
    year_of_each_event = np.repeat(np.arange(trials), events_per_year)
    return np.bincount(year_of_each_event, weights=loss_of_each_event, minlength=trials)


def summarize(yearly_losses, loss_threshold):
    """Expected loss, median, P90 (the loss exceeded in 1 year out of 10) and chance of passing the threshold."""
    exceeded_threshold = yearly_losses > loss_threshold
    return {
        "expected_loss": round(float(yearly_losses.mean())),
        "p50": round(float(np.percentile(yearly_losses, 50))),
        "p90": round(float(np.percentile(yearly_losses, 90))),
        "prob_exceed_threshold": round(float(exceeded_threshold.mean()), 4),
    }


def select_risks(register, top_n, params):
    """Pick the top_n risks: highest inherent score first, ties broken by expected loss."""
    scored_rows = []
    for row in register:
        control = params["controls"][row["Control ID"]]
        average_loss = expected_loss(control["annual_event_rate"], control["loss_median_usd"], control["loss_sigma"])
        sort_key = (-row["Inherent Risk"], -average_loss, row["Risk ID"])
        scored_rows.append((sort_key, row))

    scored_rows.sort(key=lambda scored_row: scored_row[0])

    selected = []
    for sort_key, row in scored_rows[:top_n]:
        selected.append(row)
    return selected


def run(register, params=None, trials=None, seed=None, top_n=None, threshold=None):
    """Simulate the top risks before and after remediation. Returns a dictionary of results."""
    if params is None:
        params = load_parameters()
    settings = params["monte_carlo"]

    if not trials:
        trials = settings["trials"]
    if seed is None:
        seed = settings["seed"]
    if not top_n:
        top_n = settings["top_n"]
    if not threshold:
        threshold = settings["loss_threshold_usd"]

    random_generator = np.random.default_rng(seed)
    risk_results = []
    portfolio_before = np.zeros(trials)
    portfolio_after = np.zeros(trials)

    for row in select_risks(register, top_n, params):
        control = params["controls"][row["Control ID"]]
        rate_before = control["annual_event_rate"]
        if row["Retest Status"] == "PASS":
            rate_after = rate_before * (1 - control["effectiveness_when_passing"])
        else:
            rate_after = rate_before

        losses_before = simulate(rate_before, control["loss_median_usd"], control["loss_sigma"], trials, random_generator)
        losses_after = simulate(rate_after, control["loss_median_usd"], control["loss_sigma"], trials, random_generator)
        portfolio_before = portfolio_before + losses_before
        portfolio_after = portfolio_after + losses_after

        analytic_loss = expected_loss(rate_before, control["loss_median_usd"], control["loss_sigma"])
        risk_results.append({
            "risk_id": row["Risk ID"],
            "control_id": row["Control ID"],
            "inherent_risk": row["Inherent Risk"],
            "retest_status": row["Retest Status"],
            "event_rate_before": rate_before,
            "event_rate_after": round(rate_after, 4),
            "analytic_expected_loss_before": round(analytic_loss),
            "before": summarize(losses_before, threshold),
            "after": summarize(losses_after, threshold),
        })

    # A histogram of the combined yearly loss, in 10 equal steps up to the 99.5th percentile.
    highest_loss_shown = float(np.percentile(portfolio_before, 99.5))
    bin_edges = np.linspace(0, highest_loss_shown, 11)
    counts_before = np.histogram(np.clip(portfolio_before, 0, highest_loss_shown), bins=bin_edges)[0].tolist()
    counts_after = np.histogram(np.clip(portfolio_after, 0, highest_loss_shown), bins=bin_edges)[0].tolist()
    rounded_edges = []
    for edge in bin_edges:
        rounded_edges.append(round(float(edge)))

    return {
        "assumptions": {
            "trials": trials,
            "seed": seed,
            "loss_threshold_usd": threshold,
            "top_n": top_n,
            "model": "Poisson events per year, lognormal loss per event, independent risks",
            "note": "Inputs are illustrative project assumptions in risk/risk_parameters.yaml",
        },
        "risks": risk_results,
        "portfolio": {
            "before": summarize(portfolio_before, threshold),
            "after": summarize(portfolio_after, threshold),
            "distribution": {
                "bin_edges_usd": rounded_edges,
                "counts_before": counts_before,
                "counts_after": counts_after,
            },
        },
    }


def write_results(results, path=None):
    """Save the results as JSON."""
    if path is None:
        path = ROOT / "reports" / "monte_carlo_results.json"
    path = Path(path)
    path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    return path
