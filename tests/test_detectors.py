"""Gate 2: every one of the 12 detectors must behave correctly in four situations.

   PASS          secure_state            -> every asset passes
   FAIL          insecure_state          -> exactly the expected assets fail (and the re-test shows the fix)
   INSUFFICIENT  insufficient_evidence   -> nothing is judged, nothing fails
   INPUT_ERROR   a malformed value       -> the pipeline stops before the detector runs

The expected results below were written from the design of the samples,
not copied from engine output.
"""
import pytest

from engine.evaluator import run_assessment
from tests.helpers import DetectorSpy, assets_with_status, get_detector, run_single_detector

# --- Expected results -------------------------------------------------------

# How many assets each detector checks (one finding per asset).
FINDINGS_PER_DETECTOR = {
    "DET-MFA": 1,
    "DET-EXCESS-PRIV": 1,
    "DET-INACTIVE-ACCT": 1,
    "DET-PASSWORD": 1,
    "DET-ENC-REST": 4,
    "DET-ENC-TRANSIT": 6,
    "DET-VULN-SW": 5,
    "DET-ENDPOINT": 2,
    "DET-LOGGING": 1,
    "DET-CLOUD-EXPOSURE": 3,
    "DET-BACKUP": 7,
    "DET-REMOTE-ACCESS": 1,
}

# Severity of a FAIL finding for each detector.
SEVERITY_ON_FAIL = {
    "DET-MFA": "critical",
    "DET-EXCESS-PRIV": "medium",
    "DET-INACTIVE-ACCT": "medium",
    "DET-PASSWORD": "medium",
    "DET-ENC-REST": "high",
    "DET-ENC-TRANSIT": "high",
    "DET-VULN-SW": "high",
    "DET-ENDPOINT": "high",
    "DET-LOGGING": "medium",
    "DET-CLOUD-EXPOSURE": "critical",
    "DET-BACKUP": "high",
    "DET-REMOTE-ACCESS": "critical",
}

# Assets that must FAIL in the "insecure_state" sample.
ASSETS_FAILING_IN_INSECURE_STATE = {
    "DET-MFA": {"AST-IDP-001"},
    "DET-EXCESS-PRIV": {"AST-IDP-001"},
    "DET-INACTIVE-ACCT": {"AST-IDP-001"},
    "DET-PASSWORD": {"AST-IDP-001"},
    "DET-ENC-REST": {"AST-DB-001", "AST-STO-001"},
    "DET-ENC-TRANSIT": {"AST-SRV-001", "AST-DB-001"},
    "DET-VULN-SW": {"AST-SRV-001", "AST-SRV-002"},
    "DET-ENDPOINT": {"AST-END-002"},
    "DET-LOGGING": {"AST-LOG-001"},
    "DET-CLOUD-EXPOSURE": {"AST-STO-001", "AST-STO-002"},
    "DET-BACKUP": {"AST-DB-001", "AST-STO-001", "AST-SRV-002"},
    "DET-REMOTE-ACCESS": {"AST-NET-001"},
}

# Assets that must STILL fail in "remediated_state". Everything else was fixed.
ASSETS_FAILING_AFTER_REMEDIATION = {
    "DET-MFA": set(),
    "DET-EXCESS-PRIV": {"AST-IDP-001"},
    "DET-INACTIVE-ACCT": set(),
    "DET-PASSWORD": {"AST-IDP-001"},
    "DET-ENC-REST": set(),
    "DET-ENC-TRANSIT": {"AST-SRV-001"},
    "DET-VULN-SW": {"AST-SRV-001", "AST-SRV-002"},
    "DET-ENDPOINT": {"AST-END-002"},
    "DET-LOGGING": {"AST-LOG-001"},
    "DET-CLOUD-EXPOSURE": set(),
    "DET-BACKUP": {"AST-SRV-002"},
    "DET-REMOTE-ACCESS": set(),
}

# One malformed value for each detector: (evidence block, record list, field, bad value).
# It is placed in the first record of "secure_state".
MALFORMED_VALUE = {
    "DET-MFA": ("identity", "accounts", "mfa_enforcement_status", "yes"),
    "DET-EXCESS-PRIV": ("identity", "accounts", "assigned_permissions", "read"),
    "DET-INACTIVE-ACCT": ("identity", "accounts", "last_login", "yesterday"),
    "DET-PASSWORD": ("identity", "password_policies", "minimum_password_length", -1),
    "DET-ENC-REST": ("data_protection", "at_rest", "encryption_status", "maybe"),
    "DET-ENC-TRANSIT": ("data_protection", "in_transit", "port", 70000),
    "DET-VULN-SW": ("vulnerability", "software", "cvss", 11.5),
    "DET-ENDPOINT": ("endpoint", "devices", "ip", "999.1.1.1"),
    "DET-LOGGING": ("logging", "sources", "expected_ingestion_rate", -5),
    "DET-CLOUD-EXPOSURE": ("cloud_storage", "buckets", "dlp_findings", 3),
    "DET-BACKUP": ("backup", "coverage", "retention", "a month"),
    "DET-REMOTE-ACCESS": ("access_control", "rules", "source_cidr", "0.0.0.0/33"),
}

ALL_DETECTOR_IDS = list(FINDINGS_PER_DETECTOR.keys())


# --- The four situations ----------------------------------------------------

@pytest.mark.parametrize("detector_id", ALL_DETECTOR_IDS)
def test_pass(scenario, detector_id):
    findings = run_single_detector(detector_id, scenario("secure_state"))

    assert len(findings) == FINDINGS_PER_DETECTOR[detector_id]
    for finding in findings.values():
        assert finding["status"] == "PASS"
        assert finding["severity"] == "none"


@pytest.mark.parametrize("detector_id", ALL_DETECTOR_IDS)
def test_fail_and_retest(scenario, detector_id):
    # Before remediation.
    findings = run_single_detector(detector_id, scenario("insecure_state"))
    failing_assets = assets_with_status(findings, "FAIL")
    assert failing_assets == ASSETS_FAILING_IN_INSECURE_STATE[detector_id]

    for finding in findings.values():
        assert finding["status"] in ("PASS", "FAIL")          # nothing is left undecided
        if finding["status"] == "FAIL":
            assert finding["severity"] == SEVERITY_ON_FAIL[detector_id]
            assert len(finding["evidence_ref"]) > 0           # a failure always points at evidence

    # After remediation: the SAME detector is run again on the later evidence.
    findings_after = run_single_detector(detector_id, scenario("remediated_state"))
    still_failing_assets = assets_with_status(findings_after, "FAIL")
    assert still_failing_assets == ASSETS_FAILING_AFTER_REMEDIATION[detector_id]


@pytest.mark.parametrize("detector_id", ALL_DETECTOR_IDS)
def test_insufficient(scenario, detector_id):
    findings = run_single_detector(detector_id, scenario("insufficient_evidence"))

    assert len(findings) == FINDINGS_PER_DETECTOR[detector_id]
    for finding in findings.values():
        assert finding["status"] == "INSUFFICIENT"            # absence of evidence is never a FAIL
        assert finding["evidence_status"] == "insufficient"


@pytest.mark.parametrize("detector_id", ALL_DETECTOR_IDS)
def test_input_error(scenario, detector_id):
    block, record_list, field_name, bad_value = MALFORMED_VALUE[detector_id]
    assessment = scenario("secure_state")
    assessment["evidence"][block][record_list][0][field_name] = bad_value

    spy = DetectorSpy(get_detector(detector_id))
    result = run_assessment(assessment, detectors=[spy])

    assert result["status"] == "INPUT_ERROR"
    assert spy.times_called == 0                              # the detector never saw the bad input

    finding = result["findings"][0]
    assert finding["status"] == "INPUT_ERROR"
    assert finding["detector_id"] is None
    error_paths = []
    for error in finding["errors"]:
        error_paths.append(error["path"])
    assert any(field_name in path for path in error_paths)
