"""Two-minute demo: evidence -> findings -> controls -> risk -> Monte Carlo -> remediation -> re-test.

Run it from the project folder:   python examples/end_to_end_demo.py

The demo only READS the finished risk register, remediation matrix and
decision document. It writes just the engine's own output files (findings
and Monte Carlo results) into the reports folder.
"""
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from controls.control_mapper import refs_text
from engine.evaluator import load_sample, run_assessment, write_findings
from risk import monte_carlo
from risk.risk_calculator import load_register

SAMPLES_FILE = ROOT / "inputs" / "evidence_samples.json"
REMEDIATION_MATRIX_FILE = ROOT / "remediation" / "remediation_matrix.csv"


def format_money(amount):
    return "$" + format(int(amount), ",")


def find_finding(result, detector_id):
    for finding in result["findings"]:
        if finding["detector_id"] == detector_id:
            return finding
    return None


def find_risk(register, finding_id):
    for row in register:
        if row["Finding ID"] == finding_id:
            return row
    return None


def find_remediation(detector_id):
    with open(REMEDIATION_MATRIX_FILE, newline="", encoding="utf-8") as matrix_file:
        for row in csv.DictReader(matrix_file):
            if row["Detector ID"] == detector_id:
                return row
    return None


def show(step, text):
    print(f"[{step}] {text}")


def main():
    print("SentinelBridge demo: Florence Inc. (fictional, simulated evidence)\n")

    # 1. Evidence, validation and detection.
    insecure_evidence, _ = load_sample(SAMPLES_FILE, "insecure_state")
    baseline = run_assessment(insecure_evidence)
    write_findings(baseline, ROOT / "reports" / "findings.json")
    summary = baseline["summary"]
    show("1 Evidence + validation + detection",
         f"{sum(summary.values())} findings: {summary['FAIL']} FAIL, {summary['PASS']} PASS, {summary['INSUFFICIENT']} INSUFFICIENT")

    # 2. One finding, followed through the whole chain.
    mfa_finding = find_finding(baseline, "DET-MFA")
    show("2 Finding", f"{mfa_finding['finding_id']} {mfa_finding['status']} ({mfa_finding['severity']}) detected_at {mfa_finding['detected_at']}")
    print("      " + mfa_finding["description"])

    # 3. Control mapping.
    show("3 Control mapping", f"{mfa_finding['control_id']} -> {refs_text(mfa_finding['control_id'])}")

    # 4. Risk, read from the finished risk register.
    register = load_register()
    mfa_risk = find_risk(register, mfa_finding["finding_id"])
    show("4 Risk", f"{mfa_risk['Risk ID']}: likelihood {mfa_risk['Likelihood']} x impact {mfa_risk['Impact']} = "
                   f"{mfa_risk['Inherent Risk']} ({mfa_risk['Inherent Rating']}), owner {mfa_risk['Owner']}, due {mfa_risk['Target Date']}")

    # 5. Monte Carlo uncertainty on the biggest risks.
    mc_results = monte_carlo.run(register)
    monte_carlo.write_results(mc_results)
    before = mc_results["portfolio"]["before"]
    after = mc_results["portfolio"]["after"]
    threshold = mc_results["assumptions"]["loss_threshold_usd"]
    show("5 Monte Carlo", f"top {mc_results['assumptions']['top_n']} risks, expected annual loss {format_money(before['expected_loss'])}, "
                          f"P90 {format_money(before['p90'])}, chance of exceeding {format_money(threshold)}: {before['prob_exceed_threshold']:.0%}")

    # 6. Remediation, read from the finished remediation matrix.
    remediation = find_remediation("DET-MFA")
    show("6 Remediation", f"{remediation['Remediation ID']}: {remediation['Remediation']}")
    print("      Verification: " + remediation["Verification Method"])

    # 7. Re-test: the SAME detectors run again on the later evidence.
    remediated_evidence, _ = load_sample(SAMPLES_FILE, "remediated_state")
    retest = run_assessment(remediated_evidence)
    write_findings(retest, ROOT / "reports" / "findings_retest.json")
    mfa_after = find_finding(retest, "DET-MFA")
    show("7 Re-test", f"DET-MFA on the remediated evidence: {mfa_finding['status']} -> {mfa_after['status']}")

    closed_count = 0
    for row in register:
        if row["Status"] == "Closed":
            closed_count = closed_count + 1
    print(f"      {closed_count} of {len(register)} risks closed, {len(register) - closed_count} remain open")
    show("  Residual", f"expected annual loss {format_money(before['expected_loss'])} -> {format_money(after['expected_loss'])}")

    # 8. The business decision is a finished document.
    show("8 Business decision", "see decisions/business_decision.pdf")
    print("\nFinished documents: risk/risk_register.csv, remediation/, traceability_matrix.csv, decisions/business_decision.pdf")


if __name__ == "__main__":
    main()
