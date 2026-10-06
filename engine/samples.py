"""
Builds the full evidence of one sample from the evidence samples document.
"""
import copy


class SampleNotFoundError(LookupError):
    """Raised when a sample name is not in the document."""


def find_sample(document, sample_name):
    """Return the sample with this name, or None."""
    for sample in document.get("samples", []):
        if sample.get("name") == sample_name:
            return sample
    return None


def build_sample_input(document, sample_name):
    """Return the complete assessment input of a sample. The result is a private copy."""
    sample = find_sample(document, sample_name)
    if sample is None:
        raise SampleNotFoundError(sample_name)

    # A full sample: just copy its evidence.
    if "input" in sample:
        return copy.deepcopy(sample["input"])

    # A variation: start from the sample it is based on, then apply its changes.
    assessment = build_sample_input(document, sample["based_on"])
    assessment["assessment_id"] = sample["assessment_id"]
    assessment["description"] = sample["description"]

    # "where" is judged against the base sample as it was BEFORE any change.
    original_evidence = copy.deepcopy(assessment["evidence"])
    for change in sample["changes"]:
        _apply_change(assessment["evidence"], change, original_evidence)
    return assessment


def _choose_record_ids(change, original_records):
    """Work out which records a set_fields change is about."""
    if "where" in change:
        wanted_values = change["where"]
        chosen_ids = []
        for record in original_records:
            matches = True
            for field_name, wanted_value in wanted_values.items():
                if record.get(field_name) != wanted_value:
                    matches = False
            if matches:
                chosen_ids.append(record["record_id"])
        return chosen_ids

    if change["records"] == "all":
        all_ids = []
        for record in original_records:
            all_ids.append(record["record_id"])
        return all_ids

    return change["records"]


def _apply_change(evidence, change, original_evidence):
    action = change["action"]
    block_name = change["block"]

    if action == "remove_block":
        del evidence[block_name]
        return

    list_name = change["list"]

    if action == "remove_list":
        del evidence[block_name][list_name]
        return

    if action == "replace_list":
        evidence[block_name][list_name] = copy.deepcopy(change["records"])
        return

    if action == "set_fields":
        original_records = original_evidence[block_name][list_name]
        chosen_ids = _choose_record_ids(change, original_records)
        for record in evidence[block_name][list_name]:
            if record["record_id"] in chosen_ids:
                record.update(copy.deepcopy(change["fields"]))
        return

    raise ValueError(f"unknown change action: {action}")
