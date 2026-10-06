"""Gate 1: the validators must accept good input and reject malformed input."""
import pytest

from engine.validators import validate_assessment
from engine.validators.input_validator import load_input_file

VALID_SAMPLES = ["secure_state", "insecure_state", "insufficient_evidence", "remediated_state"]


@pytest.mark.parametrize("sample_name", VALID_SAMPLES)
def test_valid_samples_pass_validation(scenario, sample_name):
    assert validate_assessment(scenario(sample_name)).valid


def test_invalid_sample_reports_every_planted_error(scenario):
    result = validate_assessment(scenario("invalid_input"))

    assert len(result.errors) == 14        # 12 schema violations and 2 evidence-rule violations
    error_paths = []
    for error in result.errors:
        error_paths.append(error["path"])
    for expected_text in ["mfa_enforcement_status", "assigned_permissions", "last_login", "minimum_password_length",
                          "encryption_status", "in_transit/0/port", "cvss", "ip", "expected_ingestion_rate",
                          "dlp_findings", "retention", "source_cidr", "asset_id", "record_id"]:
        assert any(expected_text in path for path in error_paths), expected_text


# One malformed value per control. Each must be rejected as INPUT_ERROR.
MALFORMED_VALUE_PER_CONTROL = {
    "CTRL-IAM-001": ("identity", "accounts", "mfa_enforcement_status", "yes"),
    "CTRL-IAM-002": ("identity", "accounts", "assigned_permissions", "read"),
    "CTRL-IAM-003": ("identity", "accounts", "last_login", "yesterday"),
    "CTRL-IAM-004": ("identity", "password_policies", "minimum_password_length", -1),
    "CTRL-DATA-001": ("data_protection", "at_rest", "encryption_status", "maybe"),
    "CTRL-DATA-002": ("data_protection", "in_transit", "port", 70000),
    "CTRL-END-001": ("vulnerability", "software", "cvss", 11.5),
    "CTRL-END-002": ("endpoint", "devices", "ip", "999.1.1.1"),
    "CTRL-LOG-001": ("logging", "sources", "expected_ingestion_rate", -5),
    "CTRL-CLD-001": ("cloud_storage", "buckets", "dlp_findings", 3),
    "CTRL-BCP-001": ("backup", "coverage", "retention", "a month"),
    "CTRL-NET-001": ("access_control", "rules", "source_cidr", "0.0.0.0/33"),
}


@pytest.mark.parametrize("control_id", list(MALFORMED_VALUE_PER_CONTROL.keys()))
def test_malformed_value_is_input_error(scenario, control_id):
    block, record_list, field_name, bad_value = MALFORMED_VALUE_PER_CONTROL[control_id]
    assessment = scenario("secure_state")
    assessment["evidence"][block][record_list][0][field_name] = bad_value

    result = validate_assessment(assessment)

    assert not result.valid
    assert any(field_name in error["path"] for error in result.errors)


# Missing, null and "unknown" values are NOT input errors. They become INSUFFICIENT later.
def test_missing_blocks_and_lists_are_valid(scenario):
    assessment = scenario("secure_state")
    assessment["evidence"].pop("backup")
    assessment["evidence"]["identity"].pop("password_policies")
    assert validate_assessment(assessment).valid

    assessment["evidence"] = {}
    assert validate_assessment(assessment).valid


def test_null_and_unknown_values_are_valid(scenario):
    assessment = scenario("secure_state")
    account = assessment["evidence"]["identity"]["accounts"][0]
    account["mfa_enrollment_status"] = "unknown"
    account["mfa_enforcement_status"] = None
    account["account_type"] = None
    assessment["evidence"]["cloud_storage"]["buckets"][0]["dlp_findings"] = None

    assert validate_assessment(assessment).valid


@pytest.mark.parametrize("missing_key", ["assessment_id", "organization", "collected_at", "evidence"])
def test_missing_envelope_field_is_input_error(scenario, missing_key):
    assessment = scenario("secure_state")
    del assessment[missing_key]

    assert not validate_assessment(assessment).valid


def test_bad_collected_at_is_input_error(scenario):
    assessment = scenario("secure_state")
    assessment["collected_at"] = "02/10/2026"

    assert not validate_assessment(assessment).valid


def test_unknown_field_on_a_record_is_input_error(scenario):
    assessment = scenario("secure_state")
    assessment["evidence"]["identity"]["accounts"][0]["favourite_colour"] = "blue"

    assert not validate_assessment(assessment).valid


def test_record_without_asset_id_is_input_error(scenario):
    assessment = scenario("secure_state")
    del assessment["evidence"]["identity"]["accounts"][0]["asset_id"]

    assert not validate_assessment(assessment).valid


def test_badly_formed_asset_id_is_input_error(scenario):
    assessment = scenario("secure_state")
    assessment["evidence"]["identity"]["accounts"][0]["asset_id"] = "IDP-1"

    assert not validate_assessment(assessment).valid


def test_block_without_source_is_input_error(scenario):
    assessment = scenario("secure_state")
    del assessment["evidence"]["backup"]["source"]

    assert not validate_assessment(assessment).valid


def test_unknown_evidence_block_is_input_error(scenario):
    assessment = scenario("secure_state")
    assessment["evidence"]["email"] = {"source": "mailbox export"}

    assert not validate_assessment(assessment).valid


def test_unknown_asset_and_duplicate_record_id_are_input_errors(scenario):
    assessment = scenario("secure_state")
    assessment["evidence"]["identity"]["accounts"][0]["asset_id"] = "AST-ZZZ-999"
    assessment["evidence"]["endpoint"]["devices"][1]["record_id"] = "DEV-0001"

    result = validate_assessment(assessment)

    all_messages = " ".join(error["message"] for error in result.errors)
    assert "not in the inventory" in all_messages
    assert "duplicate record_id" in all_messages


def test_custom_asset_list_is_respected(scenario):
    result = validate_assessment(scenario("secure_state"), asset_ids={"AST-IDP-001"})

    assert not result.valid


def test_malformed_json_file_is_input_error(tmp_path):
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{ not json", encoding="utf-8")

    data, result = load_input_file(bad_file)
    assert data is None
    assert not result.valid

    data, result = load_input_file(tmp_path / "missing.json")
    assert data is None
    assert "not found" in result.errors[0]["message"]
