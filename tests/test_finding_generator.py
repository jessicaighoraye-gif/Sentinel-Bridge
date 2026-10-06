from datetime import datetime, timezone

from engine.detectors.base_detector import AssetResult
from engine.detectors.identity.mfa_detector import MfaDetector
from engine.finding_generator import make_finding, make_input_error_finding
from engine.validators import validate_finding


def test_detected_at_is_generated_by_the_engine():
    pinned_clock = lambda: datetime(2026, 10, 2, 9, 30, 12, tzinfo=timezone.utc)
    result = AssetResult("AST-IDP-001", "FAIL", "critical", ["identity:ACC-0003"], "example description")

    finding = make_finding("ASM-TEST-1", MfaDetector(), result, 1, pinned_clock)

    assert finding["detected_at"] == "2026-10-02T09:30:12Z"
    assert finding["finding_id"] == "FND-MFA-01"
    assert validate_finding(finding).valid


def test_input_error_finding_without_a_usable_assessment_id():
    errors = [{"path": "(root)", "message": "example"}]

    finding = make_input_error_finding({"assessment_id": "bad id"}, errors)

    assert finding["assessment_id"] == "ASM-UNKNOWN"
    assert finding["finding_id"] == "FND-INPUT-01"
    assert validate_finding(finding).valid
