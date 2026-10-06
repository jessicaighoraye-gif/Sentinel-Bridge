"""Gate 1: the finding record format (inputs/schema/finding.schema.json)."""
import copy

import pytest

from engine.validators import validate_finding

FAIL_FINDING = {
    "finding_id": "FND-MFA-01",
    "assessment_id": "ASM-FLORENCE-0001",
    "detector_id": "DET-MFA",
    "control_id": "CTRL-IAM-001",
    "asset_id": "AST-IDP-001",
    "status": "FAIL",
    "severity": "critical",
    "detected_at": "2026-10-02T09:30:12Z",
    "evidence_status": "sufficient",
    "evidence_ref": ["identity:ACC-0007"],
    "description": "3 of 12 privileged accounts lack MFA.",
}


def changed(**changes):
    """A copy of the FAIL finding with some fields changed."""
    finding = copy.deepcopy(FAIL_FINDING)
    finding.update(changes)
    return finding


PASS_FINDING = changed(status="PASS", severity="none")
INSUFFICIENT_FINDING = changed(status="INSUFFICIENT", severity="none", evidence_status="insufficient", evidence_ref=[])
INPUT_ERROR_FINDING = changed(
    finding_id="FND-INPUT-01", assessment_id="ASM-UNKNOWN", detector_id=None, control_id=None, asset_id=None,
    status="INPUT_ERROR", severity="none", evidence_status="invalid", evidence_ref=[],
    errors=[{"path": "evidence/identity", "message": "bad"}],
)


@pytest.mark.parametrize("finding", [FAIL_FINDING, PASS_FINDING, INSUFFICIENT_FINDING, INPUT_ERROR_FINDING],
                         ids=["FAIL", "PASS", "INSUFFICIENT", "INPUT_ERROR"])
def test_valid_findings(finding):
    assert validate_finding(finding).valid


def finding_without(finding, field_name):
    copy_of_finding = copy.deepcopy(finding)
    del copy_of_finding[field_name]
    return copy_of_finding


INVALID_FINDINGS = {
    "fail-with-severity-none": changed(severity="none"),
    "pass-with-severity-high": changed(status="PASS", severity="high"),
    "fail-without-evidence": changed(evidence_ref=[]),
    "insufficient-marked-sufficient": changed(status="INSUFFICIENT", severity="none"),
    "input-error-with-a-detector": changed(status="INPUT_ERROR", severity="none", evidence_status="invalid",
                                           errors=[{"path": "x", "message": "y"}]),
    "input-error-without-errors": finding_without(INPUT_ERROR_FINDING, "errors"),
    "missing-detected-at": finding_without(FAIL_FINDING, "detected_at"),
    "bad-detected-at": changed(detected_at="today"),
    "bad-evidence-reference": changed(evidence_ref=["ACC-0007"]),
    "unknown-status": changed(status="MAYBE"),
}


@pytest.mark.parametrize("case_name", list(INVALID_FINDINGS.keys()))
def test_invalid_findings(case_name):
    assert not validate_finding(INVALID_FINDINGS[case_name]).valid
