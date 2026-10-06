"""Turns detector results into finding records. detected_at is created here, by the engine."""
import re

from engine.timestamp import utc_now
from engine.validators import validate_finding

ASSESSMENT_ID_PATTERN = re.compile(r"^ASM-[A-Z0-9-]{3,40}$")


def _check_finding(finding):
    """Every finding must match finding.schema.json. If not, the engine has a bug."""
    validation = validate_finding(finding)
    if not validation.valid:
        raise ValueError(f"engine produced an invalid finding: {validation.errors[:2]}")
    return finding


def make_finding(assessment_id, detector, result, sequence_number, clock=None):
    """Build the finding for one detector result. IDs look like FND-MFA-01."""
    detector_key = detector.DETECTOR_ID[len("DET-"):]

    if result.status in ("PASS", "FAIL"):
        evidence_status = "sufficient"
    else:
        evidence_status = "insufficient"

    finding = {
        "finding_id": f"FND-{detector_key}-{sequence_number:02d}",
        "assessment_id": assessment_id,
        "detector_id": detector.DETECTOR_ID,
        "control_id": detector.CONTROL_ID,
        "asset_id": result.asset_id,
        "status": result.status,
        "severity": result.severity,
        "detected_at": utc_now(clock),
        "evidence_status": evidence_status,
        "evidence_ref": result.evidence_ref,
        "description": result.description,
    }
    return _check_finding(finding)


def make_input_error_finding(data, errors, clock=None):
    """Build the single finding that reports a rejected input. No detector ran, so those fields are None."""
    assessment_id = None
    if isinstance(data, dict):
        assessment_id = data.get("assessment_id")

    id_is_usable = isinstance(assessment_id, str) and ASSESSMENT_ID_PATTERN.match(assessment_id)
    if not id_is_usable:
        assessment_id = "ASM-UNKNOWN"

    finding = {
        "finding_id": "FND-INPUT-01",
        "assessment_id": assessment_id,
        "detector_id": None,
        "control_id": None,
        "asset_id": None,
        "status": "INPUT_ERROR",
        "severity": "none",
        "detected_at": utc_now(clock),
        "evidence_status": "invalid",
        "evidence_ref": [],
        "description": f"Input rejected with {len(errors)} validation error(s). No detector was run.",
        "errors": errors,
    }
    return _check_finding(finding)


def generate_findings(assessment_id, detector_results, clock=None):
    """detector_results is a list of (detector, [AssetResult]). Findings are numbered per detector."""
    findings = []
    for detector, asset_results in detector_results:
        sequence_number = 1
        for result in asset_results:
            findings.append(make_finding(assessment_id, detector, result, sequence_number, clock))
            sequence_number = sequence_number + 1
    return findings
