"""Gate 2 integration: Input -> Validation -> Detection -> Finding."""
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from engine.evaluator import default_detectors, main, run_assessment, run_file
from engine.validators import validate_finding

SAMPLES_FILE = str(Path(__file__).resolve().parents[1] / "inputs" / "evidence_samples.json")


def test_twelve_detectors_match_the_twelve_controls():
    detectors = default_detectors()
    assert len(detectors) == 12

    detector_ids = set()
    control_ids = set()
    for detector in detectors:
        detector_ids.add(detector.DETECTOR_ID)
        control_ids.add(detector.CONTROL_ID)
    assert len(detector_ids) == 12
    assert control_ids == {
        "CTRL-IAM-001", "CTRL-IAM-002", "CTRL-IAM-003", "CTRL-IAM-004", "CTRL-DATA-001", "CTRL-DATA-002",
        "CTRL-END-001", "CTRL-END-002", "CTRL-LOG-001", "CTRL-CLD-001", "CTRL-BCP-001", "CTRL-NET-001",
    }


@pytest.mark.parametrize("sample_name,expected_summary", [
    ("secure_state", {"PASS": 33, "FAIL": 0, "INSUFFICIENT": 0, "INPUT_ERROR": 0}),
    ("insecure_state", {"PASS": 15, "FAIL": 18, "INSUFFICIENT": 0, "INPUT_ERROR": 0}),
    ("insufficient_evidence", {"PASS": 0, "FAIL": 0, "INSUFFICIENT": 33, "INPUT_ERROR": 0}),
    ("remediated_state", {"PASS": 25, "FAIL": 8, "INSUFFICIENT": 0, "INPUT_ERROR": 0}),
    ("invalid_input", {"PASS": 0, "FAIL": 0, "INSUFFICIENT": 0, "INPUT_ERROR": 1}),
])
def test_summary_of_each_original_sample(scenario, sample_name, expected_summary):
    assert run_assessment(scenario(sample_name))["summary"] == expected_summary


def test_every_finding_is_valid_unique_and_points_at_real_evidence(scenario):
    assessment = scenario("insecure_state")
    result = run_assessment(assessment)

    finding_ids = []
    for finding in result["findings"]:
        finding_ids.append(finding["finding_id"])
    assert len(finding_ids) == 33
    assert len(set(finding_ids)) == 33

    # Collect every evidence record as "block:record_id" so references can be checked.
    all_record_references = set()
    for block_name, block in assessment["evidence"].items():
        for list_name, records in block.items():
            if list_name == "source":
                continue
            for record in records:
                all_record_references.add(f"{block_name}:{record['record_id']}")

    for finding in result["findings"]:
        assert validate_finding(finding).valid
        assert finding["assessment_id"] == "ASM-FLORENCE-INSECURE"
        for reference in finding["evidence_ref"]:
            assert reference in all_record_references


def test_detected_at_comes_from_the_engine_not_the_evidence(scenario):
    assessment = scenario("secure_state")
    pinned_clock = lambda: datetime(2030, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    result = run_assessment(assessment, clock=pinned_clock)

    for finding in result["findings"]:
        assert finding["detected_at"] == "2030-01-01T12:00:00Z"
    assert assessment["collected_at"] != "2030-01-01T12:00:00Z"


def status_by_detector_and_asset(result):
    statuses = {}
    for finding in result["findings"]:
        statuses[(finding["detector_id"], finding["asset_id"])] = finding["status"]
    return statuses


def test_remediation_flips_fail_to_pass_without_regressions(scenario):
    before = status_by_detector_and_asset(run_assessment(scenario("insecure_state")))
    after = status_by_detector_and_asset(run_assessment(scenario("remediated_state")))

    fixed = []
    regressed = []
    for key in before:
        if before[key] == "FAIL" and after[key] == "PASS":
            fixed.append(key)
        if before[key] == "PASS" and after[key] != "PASS":
            regressed.append(key)

    assert len(fixed) == 10
    assert regressed == []


def test_invalid_input_gives_one_input_error_finding(scenario):
    result = run_assessment(scenario("invalid_input"))

    assert result["status"] == "INPUT_ERROR"
    assert len(result["findings"]) == 1
    assert result["findings"][0]["finding_id"] == "FND-INPUT-01"
    assert len(result["findings"][0]["errors"]) == 14


def test_unreadable_file_is_input_error_not_a_crash(tmp_path):
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{ nope", encoding="utf-8")

    assert run_file(bad_file)["status"] == "INPUT_ERROR"
    assert run_file(tmp_path / "missing.json")["status"] == "INPUT_ERROR"


def test_command_line_runs_a_named_sample_and_writes_findings(tmp_path):
    output_file = tmp_path / "out" / "findings.json"

    exit_code = main([SAMPLES_FILE, "--sample", "insecure_state", "--out", str(output_file)])

    saved = json.loads(output_file.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert saved["summary"]["FAIL"] == 18
    assert len(saved["findings"]) == 33

    assert main([SAMPLES_FILE, "--sample", "invalid_input", "--out", str(output_file)]) == 2
    assert main([SAMPLES_FILE, "--sample", "no_such_sample", "--out", str(output_file)]) == 2


def test_command_line_without_a_sample_lists_the_choices(tmp_path):
    assert main([SAMPLES_FILE, "--out", str(tmp_path / "unused.json")]) == 1
