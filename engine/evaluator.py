"""The pipeline: input -> validation -> detection -> findings.

Run it from the project folder:
    python -m engine.evaluator inputs/evidence_samples.json --sample insecure_state
"""
import argparse
import json
from pathlib import Path

from engine.detectors import ALL_DETECTOR_CLASSES
from engine.detectors.base_detector import Context
from engine.finding_generator import generate_findings, make_input_error_finding
from engine.samples import SampleNotFoundError, build_sample_input
from engine.validators import ValidationResult, load_input_file, validate_assessment

ROOT = Path(__file__).resolve().parents[1]
STATUSES = ("PASS", "FAIL", "INSUFFICIENT", "INPUT_ERROR")


def default_detectors():
    """One instance of each of the 12 detectors."""
    detectors = []
    for detector_class in ALL_DETECTOR_CLASSES:
        detectors.append(detector_class())
    return detectors


def _summarize(findings):
    """Count findings by status, for example {"PASS": 15, "FAIL": 18, ...}."""
    summary = {}
    for status in STATUSES:
        summary[status] = 0
    for finding in findings:
        summary[finding["status"]] = summary[finding["status"]] + 1
    return summary


def _input_error_result(data, errors, clock):
    finding = make_input_error_finding(data, errors, clock)
    return {
        "assessment_id": finding["assessment_id"],
        "collected_at": None,
        "status": "INPUT_ERROR",
        "summary": _summarize([finding]),
        "findings": [finding],
    }


def run_assessment(data, detectors=None, clock=None):
    """Validate the input first. Bad input gives one INPUT_ERROR finding and no detector runs."""
    validation = validate_assessment(data)
    if not validation.valid:
        return _input_error_result(data, validation.errors, clock)

    context = Context.build(data["collected_at"])
    if detectors is None:
        detectors = default_detectors()

    detector_results = []
    for detector in detectors:
        asset_results = detector.evaluate(data, context)
        detector_results.append((detector, asset_results))

    findings = generate_findings(data["assessment_id"], detector_results, clock)
    return {
        "assessment_id": data["assessment_id"],
        "collected_at": data["collected_at"],
        "status": "COMPLETED",
        "summary": _summarize(findings),
        "findings": findings,
    }


def run_file(path, detectors=None, clock=None):
    """Run one assessment stored in its own JSON file."""
    data, load_result = load_input_file(path)
    if not load_result.valid:
        return _input_error_result(None, load_result.errors, clock)
    return run_assessment(data, detectors, clock)


def sample_names(document):
    """The names of all samples in an evidence samples document."""
    names = []
    for sample in document.get("samples", []):
        names.append(sample.get("name"))
    return names


def load_sample(path, sample_name):
    """Read one named sample out of the evidence samples document. Returns (input, ValidationResult)."""
    document, load_result = load_input_file(path)
    if not load_result.valid:
        return None, load_result

    try:
        return build_sample_input(document, sample_name), ValidationResult()
    except SampleNotFoundError:
        error = {"path": str(path), "message": f"sample '{sample_name}' not found"}
        return None, ValidationResult([error])


def write_findings(result, path):
    """Save the result as findings JSON. This is the engine's output file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run SentinelBridge on a security input file.")
    parser.add_argument("input", help="an assessment JSON file, or the evidence samples document")
    parser.add_argument("--sample", help="name of the sample to run when the input is the samples document")
    parser.add_argument("--out", default=str(ROOT / "reports" / "findings.json"), help="where to write the findings")
    arguments = parser.parse_args(argv)

    if arguments.sample:
        data, load_result = load_sample(arguments.input, arguments.sample)
        if load_result.valid:
            result = run_assessment(data)
        else:
            result = _input_error_result(None, load_result.errors, None)
    else:
        document, _ = load_input_file(arguments.input)
        if isinstance(document, dict) and "samples" in document:
            print("This file holds several samples. Choose one with --sample. Available:")
            for name in sample_names(document):
                print("  " + name)
            return 1
        result = run_file(arguments.input)

    output_path = write_findings(result, arguments.out)
    summary = result["summary"]
    print(
        f"{result['assessment_id']}: {result['status']} | PASS {summary['PASS']} FAIL {summary['FAIL']} "
        f"INSUFFICIENT {summary['INSUFFICIENT']} INPUT_ERROR {summary['INPUT_ERROR']} | wrote {output_path}"
    )
    if result["status"] == "INPUT_ERROR":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
