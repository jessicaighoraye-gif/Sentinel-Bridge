from .evidence_validator import load_asset_ids, validate_evidence
from .input_validator import ValidationResult, load_input_file, validate_finding, validate_schema


def validate_assessment(data, asset_ids=None):
    """Run the schema check and the evidence rules. Any error means INPUT_ERROR."""
    schema_result = validate_schema(data)
    evidence_result = validate_evidence(data, asset_ids)

    all_errors = schema_result.errors + evidence_result.errors
    all_errors.sort(key=lambda error: (error["path"], error["message"]))
    return ValidationResult(all_errors)
