"""Risk formulas and the files they depend on. See docs/06_risk_methodology.md.

  Inherent risk = Likelihood x Impact                      (a number from 1 to 25)
  Residual risk = Inherent risk x (1 - control effectiveness)

The risk register itself (risk/risk_register.csv) is a finished, hand-checked
file. Nothing in this project writes it. This module only holds the formulas
and the loaders that the tests and the Monte Carlo analysis use.
"""
import csv
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RISK_REGISTER_FILE = ROOT / "risk" / "risk_register.csv"

REGISTER_COLUMNS = [
    "Risk ID", "Finding ID", "Control ID", "Asset", "Threat", "Likelihood", "Impact", "Inherent Risk",
    "Inherent Rating", "Control Effectiveness", "Residual Risk", "Treatment", "Owner", "Target Date", "Status",
    "Retest Status", "Residual After Retest", "Rating After Retest",
]
WHOLE_NUMBER_COLUMNS = ("Likelihood", "Impact", "Inherent Risk")
DECIMAL_COLUMNS = ("Control Effectiveness", "Residual Risk", "Residual After Retest")

LOWEST_SCALE_VALUE = 1
HIGHEST_SCALE_VALUE = 5

_cached_files = {}


def _read_yaml(relative_path):
    """Read a YAML file once and remember it."""
    if relative_path not in _cached_files:
        full_path = ROOT / relative_path
        _cached_files[relative_path] = yaml.safe_load(full_path.read_text(encoding="utf-8"))
    return _cached_files[relative_path]


def load_parameters():
    """Scales, rating bands and the Monte Carlo inputs (risk/risk_parameters.yaml)."""
    return _read_yaml("risk/risk_parameters.yaml")


def load_decision_matrix():
    """Treatment, target days and approver for each rating band."""
    return _read_yaml("decisions/decision_matrix.yaml")


def load_remediation_rules():
    """Remediation text and effort for each detector."""
    return _read_yaml("remediation/remediation_rules.yaml")["rules"]


def load_assets():
    """The asset inventory as {asset_id: asset}."""
    assets_by_id = {}
    for asset in _read_yaml("company/asset_inventory.yaml")["assets"]:
        assets_by_id[asset["asset_id"]] = asset
    return assets_by_id


def _check_scale_value(name, value):
    """Likelihood and impact must be whole numbers from 1 to 5."""
    is_whole_number = isinstance(value, int) and not isinstance(value, bool)
    if not is_whole_number or value < LOWEST_SCALE_VALUE or value > HIGHEST_SCALE_VALUE:
        raise ValueError(f"{name} must be an integer from 1 to 5, got {value!r}")


def inherent_score(likelihood, impact):
    """Inherent risk = likelihood x impact."""
    _check_scale_value("likelihood", likelihood)
    _check_scale_value("impact", impact)
    return likelihood * impact


def rating(score):
    """Turn a score from 1 to 25 into Low, Medium, High or Critical."""
    if score < 1 or score > 25:
        raise ValueError(f"score must be between 1 and 25, got {score!r}")

    for band in load_parameters()["rating_bands"]:
        if score <= band["max"]:
            return band["name"]
    raise ValueError(f"no band for score {score!r}")


def residual_score(inherent, effectiveness):
    """Risk that is left after controls. Effectiveness is 0 (useless) to 1 (perfect)."""
    if effectiveness < 0 or effectiveness > 1:
        raise ValueError(f"effectiveness must be between 0 and 1, got {effectiveness!r}")
    return round(inherent * (1 - effectiveness), 1)


def impact_for(criticality):
    """Impact comes from how critical the affected asset is: low 2, medium 3, high 4, critical 5."""
    return load_parameters()["scales"]["impact_from_criticality"][criticality]


def load_register(path=None):
    """Read the risk register CSV. Numbers are converted from text so they can be used in maths."""
    if path is None:
        path = RISK_REGISTER_FILE

    rows = []
    with open(path, newline="", encoding="utf-8") as register_file:
        for row in csv.DictReader(register_file):
            for column in WHOLE_NUMBER_COLUMNS:
                row[column] = int(row[column])
            for column in DECIMAL_COLUMNS:
                row[column] = float(row[column])
            rows.append(row)
    return rows
