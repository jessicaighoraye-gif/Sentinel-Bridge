"""Step 1 of the pipeline: check the input against the JSON schemas.

If the input is malformed the engine stops here and reports INPUT_ERROR.
No detector ever sees bad input.
"""
import json
from dataclasses import dataclass, field
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_FOLDER = ROOT / "inputs" / "schema"
SCHEMA_FILE_NAMES = (
    "security_input.schema.json",   # the outer envelope of one assessment
    "evidence.schema.json",         # the 8 evidence blocks inside it
    "finding.schema.json",          # the format of one finding
)

MAX_MESSAGE_LENGTH = 200


@dataclass
class ValidationResult:

    errors: list = field(default_factory=list)

    @property
    def valid(self):
        return len(self.errors) == 0


# The validators are built once and reused, because reading the schemas is slow.
_cached_validators = None


def _build_validators():
    """Return (input_validator, finding_validator)."""
    global _cached_validators
    if _cached_validators is not None:
        return _cached_validators

    schemas = {}
    for file_name in SCHEMA_FILE_NAMES:
        schema_text = (SCHEMA_FOLDER / file_name).read_text(encoding="utf-8")
        schemas[file_name] = json.loads(schema_text)

    # security_input.schema.json refers to evidence.schema.json, so the
    # validator needs a registry that knows where to find every schema.
    registry = Registry()
    for schema in schemas.values():
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))

    input_validator = Draft202012Validator(schemas["security_input.schema.json"], registry=registry)
    finding_validator = Draft202012Validator(schemas["finding.schema.json"], registry=registry)
    _cached_validators = (input_validator, finding_validator)
    return _cached_validators


def _error_sort_key(error):
    return (error["path"], error["message"])


def _collect_errors(validator, data):
    """Run a validator and return a sorted list of {"path", "message"} errors."""
    errors = []
    for schema_error in validator.iter_errors(data):
        path_parts = []
        for part in schema_error.absolute_path:
            path_parts.append(str(part))
        path_text = "/".join(path_parts)
        if path_text == "":
            path_text = "(root)"

        errors.append({"path": path_text, "message": schema_error.message[:MAX_MESSAGE_LENGTH]})

    errors.sort(key=_error_sort_key)
    return ValidationResult(errors)


def validate_schema(data):
    """Check one assessment input against security_input.schema.json."""
    input_validator, _ = _build_validators()
    return _collect_errors(input_validator, data)


def validate_finding(finding):
    """Check one finding record against finding.schema.json."""
    _, finding_validator = _build_validators()
    return _collect_errors(finding_validator, finding)


def load_input_file(path):
    """Read a JSON file. Returns (data, ValidationResult).

    A missing or unreadable file is reported as an INPUT_ERROR instead of crashing.
    """
    path = Path(path)
    try:
        file_text = path.read_text(encoding="utf-8")
        data = json.loads(file_text)
        return data, ValidationResult()
    except FileNotFoundError:
        error = {"path": str(path), "message": "file not found"}
        return None, ValidationResult([error])
    except (json.JSONDecodeError, UnicodeDecodeError) as problem:
        message = f"not valid JSON: {problem}"[:MAX_MESSAGE_LENGTH]
        return None, ValidationResult([{"path": str(path), "message": message}])
