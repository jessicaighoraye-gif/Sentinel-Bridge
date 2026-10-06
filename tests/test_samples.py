"""The evidence samples document: 30 hypothetical samples in one file.

Every sample states the result the engine must produce ("expected_summary").
These expectations were produced by a separate reference evaluator, so this
test checks the engine against an independent source.
"""
import pytest

from engine.evaluator import run_assessment
from engine.samples import SampleNotFoundError, build_sample_input
from tests.conftest import load_samples_document

SAMPLES = load_samples_document()["samples"]
SAMPLE_NAMES = [sample["name"] for sample in SAMPLES]
ORIGINAL_NAMES = ["secure_state", "insecure_state", "insufficient_evidence", "invalid_input", "remediated_state"]


def test_document_holds_30_unique_samples_with_the_original_five():
    assert len(SAMPLES) == 30
    assert len(set(SAMPLE_NAMES)) == 30
    for original_name in ORIGINAL_NAMES:
        assert original_name in SAMPLE_NAMES


def test_originals_hold_full_evidence_and_variations_hold_only_changes():
    for sample in SAMPLES:
        if sample["name"] in ORIGINAL_NAMES:
            assert "input" in sample
            assert "changes" not in sample
        else:
            assert "changes" in sample and "based_on" in sample
            assert "input" not in sample
            assert sample["based_on"] in SAMPLE_NAMES


@pytest.mark.parametrize("sample_name", SAMPLE_NAMES)
def test_engine_produces_the_expected_summary(scenario, sample_name):
    sample = None
    for candidate in SAMPLES:
        if candidate["name"] == sample_name:
            sample = candidate

    result = run_assessment(scenario(sample_name))

    assert result["summary"] == sample["expected_summary"]


SINGLE_CONTROL_SAMPLE_NAMES = [name for name in SAMPLE_NAMES if name.startswith("only_")]


@pytest.mark.parametrize("sample_name", SINGLE_CONTROL_SAMPLE_NAMES)
def test_single_control_samples_change_only_that_control(scenario, sample_name):
    is_fail_sample = sample_name.endswith("_fails")
    is_insufficient_sample = sample_name.endswith("_insufficient")
    assert is_fail_sample or is_insufficient_sample

    result = run_assessment(scenario(sample_name))

    detectors_with_problems = set()
    for finding in result["findings"]:
        if finding["status"] != "PASS":
            detectors_with_problems.add(finding["detector_id"])
    assert len(detectors_with_problems) == 1                  # exactly one control is affected

    wanted_status = "FAIL" if is_fail_sample else "INSUFFICIENT"
    unwanted_status = "INSUFFICIENT" if is_fail_sample else "FAIL"
    assert result["summary"][wanted_status] >= 1
    assert result["summary"][unwanted_status] == 0            # missing evidence never becomes a failure


# --- How a variation is rebuilt from its changes (tested on a tiny made-up document) ---

def tiny_document():
    accounts = [
        {"record_id": "ACC-0001", "account_type": "human", "mfa": "on"},
        {"record_id": "ACC-0002", "account_type": "service", "mfa": "on"},
        {"record_id": "ACC-0003", "account_type": "human", "mfa": "on"},
    ]
    base_input = {
        "assessment_id": "ASM-BASE-1",
        "description": "the base",
        "evidence": {
            "identity": {"source": "s", "accounts": accounts},
            "logging": {"source": "s", "sources": [{"record_id": "LOG-0001", "required_source": True}]},
        },
    }
    variation = {"name": "variation", "based_on": "base", "assessment_id": "ASM-VARIATION-1", "description": "the variation"}
    return {"samples": [{"name": "base", "input": base_input}, variation]}


def build_variation(changes):
    document = tiny_document()
    document["samples"][1]["changes"] = changes
    return build_sample_input(document, "variation")


def mfa_values(assessment):
    values = []
    for account in assessment["evidence"]["identity"]["accounts"]:
        values.append(account["mfa"])
    return values


def test_set_fields_by_record_id():
    change = {"action": "set_fields", "block": "identity", "list": "accounts", "records": ["ACC-0003"], "fields": {"mfa": "off"}}

    assert mfa_values(build_variation([change])) == ["on", "on", "off"]


def test_set_fields_by_where_picks_records_by_their_values():
    change = {"action": "set_fields", "block": "identity", "list": "accounts", "where": {"account_type": "human"}, "fields": {"mfa": "off"}}

    assert mfa_values(build_variation([change])) == ["off", "on", "off"]


def test_set_fields_for_all_records():
    change = {"action": "set_fields", "block": "identity", "list": "accounts", "records": "all", "fields": {"mfa": "off"}}

    assert mfa_values(build_variation([change])) == ["off", "off", "off"]


def test_replace_remove_list_and_remove_block():
    replaced = build_variation([{"action": "replace_list", "block": "logging", "list": "sources", "records": []}])
    assert replaced["evidence"]["logging"]["sources"] == []

    list_removed = build_variation([{"action": "remove_list", "block": "logging", "list": "sources"}])
    assert "sources" not in list_removed["evidence"]["logging"]

    block_removed = build_variation([{"action": "remove_block", "block": "logging"}])
    assert "logging" not in block_removed["evidence"]


def test_variation_gets_its_own_id_and_description_and_the_base_is_untouched():
    document = tiny_document()
    document["samples"][1]["changes"] = [
        {"action": "set_fields", "block": "identity", "list": "accounts", "records": "all", "fields": {"mfa": "off"}}]

    variation = build_sample_input(document, "variation")
    base = build_sample_input(document, "base")

    assert variation["assessment_id"] == "ASM-VARIATION-1"
    assert variation["description"] == "the variation"
    assert mfa_values(base) == ["on", "on", "on"]


def test_unknown_action_and_unknown_sample_are_rejected():
    with pytest.raises(ValueError):
        build_variation([{"action": "explode", "block": "logging", "list": "sources"}])
    with pytest.raises(SampleNotFoundError):
        build_sample_input(tiny_document(), "no_such_sample")
