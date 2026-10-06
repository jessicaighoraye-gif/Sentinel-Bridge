"""The risk register (risk/risk_register.csv) is a finished file that no code writes.

These tests recompute what every row SHOULD say from the engine's findings and
the formulas, then compare it with the file. They also guard the rule that no
project code may write a CSV file.
"""
from datetime import timedelta
from pathlib import Path

from engine.evaluator import run_assessment
from engine.timestamp import parse_timestamp
from risk import risk_calculator

ROOT = Path(__file__).resolve().parents[1]


def failing_findings(result):
    failing = []
    for finding in result["findings"]:
        if finding["status"] == "FAIL":
            failing.append(finding)
    return failing


def find_status(result, detector_id, asset_id):
    for finding in result["findings"]:
        if finding["detector_id"] == detector_id and finding["asset_id"] == asset_id:
            return finding["status"]
    return "NOT RETESTED"


def work_out_expected_row(finding, retest_status, baseline_collected_at):
    """What the register should say for one failing finding."""
    parameters = risk_calculator.load_parameters()
    decision_matrix = risk_calculator.load_decision_matrix()
    remediation_rules = risk_calculator.load_remediation_rules()
    asset = risk_calculator.load_assets()[finding["asset_id"]]
    control = parameters["controls"][finding["control_id"]]

    likelihood = control["likelihood"]
    impact = risk_calculator.impact_for(asset["criticality"])
    inherent = risk_calculator.inherent_score(likelihood, impact)
    band = risk_calculator.rating(inherent)

    effort = remediation_rules[finding["detector_id"]]["effort"]
    band_rules = decision_matrix["bands"][band]
    due_date = parse_timestamp(baseline_collected_at) + timedelta(days=band_rules["target_days"])

    # The control is failing today, so it gives no protection. After a passing retest it does.
    effectiveness_now = 0.0
    if retest_status == "PASS":
        effectiveness_after = control["effectiveness_when_passing"]
    else:
        effectiveness_after = 0.0
    residual_after_retest = risk_calculator.residual_score(inherent, effectiveness_after)

    detector_key_and_number = finding["finding_id"][len("FND-"):]
    return {
        "Risk ID": "RISK-" + detector_key_and_number,
        "Finding ID": finding["finding_id"],
        "Control ID": finding["control_id"],
        "Asset": f"{asset['asset_id']} {asset['name']}",
        "Threat": control["threat"],
        "Likelihood": likelihood,
        "Impact": impact,
        "Inherent Risk": inherent,
        "Inherent Rating": band,
        "Control Effectiveness": effectiveness_now,
        "Residual Risk": risk_calculator.residual_score(inherent, effectiveness_now),
        "Treatment": band_rules["treatment_by_effort"][effort],
        "Owner": asset["owner_role"],
        "Target Date": due_date.strftime("%Y-%m-%d"),
        "Status": "Closed" if retest_status == "PASS" else "Open",
        "Retest Status": retest_status,
        "Residual After Retest": residual_after_retest,
        "Rating After Retest": risk_calculator.rating(max(residual_after_retest, 1)),
    }


def test_register_has_the_expected_columns_and_one_row_per_failing_finding(scenario):
    register = risk_calculator.load_register()
    baseline = run_assessment(scenario("insecure_state"))

    assert list(register[0].keys()) == risk_calculator.REGISTER_COLUMNS
    assert len(register) == len(failing_findings(baseline)) == 18

    risk_ids = set()
    for row in register:
        risk_ids.add(row["Risk ID"])
    assert len(risk_ids) == 18


def test_every_register_row_matches_the_engine_and_the_formulas(scenario):
    register = risk_calculator.load_register()
    baseline = run_assessment(scenario("insecure_state"))
    retest = run_assessment(scenario("remediated_state"))

    register_by_finding = {}
    for row in register:
        register_by_finding[row["Finding ID"]] = row

    for finding in failing_findings(baseline):
        retest_status = find_status(retest, finding["detector_id"], finding["asset_id"])
        expected_row = work_out_expected_row(finding, retest_status, baseline["collected_at"])
        actual_row = register_by_finding[finding["finding_id"]]
        for column in risk_calculator.REGISTER_COLUMNS:
            assert actual_row[column] == expected_row[column], (finding["finding_id"], column)


def test_register_tells_the_retest_story():
    register = risk_calculator.load_register()

    closed = []
    open_after_retest = []
    for row in register:
        if row["Status"] == "Closed":
            closed.append(row)
        else:
            open_after_retest.append(row)

    assert len(closed) == 10
    assert len(open_after_retest) == 8
    for row in open_after_retest:
        assert row["Rating After Retest"] != "Critical"        # every critical risk was closed


def test_no_python_file_writes_a_csv():
    forbidden_text = ["csv.writer", "DictWriter", "to_csv", ".writerow"]
    folders_to_scan = ["engine", "risk", "controls", "examples", "tests"]

    for folder in folders_to_scan:
        for python_file in (ROOT / folder).rglob("*.py"):
            if python_file.name == "test_risk_register.py":
                continue                                          # this file names the words it forbids
            source_code = python_file.read_text(encoding="utf-8")
            for text in forbidden_text:
                assert text not in source_code, f"{python_file} contains {text}"
