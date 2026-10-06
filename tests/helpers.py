"""Small helpers shared by the detector tests."""
from engine.evaluator import default_detectors, run_assessment


def get_detector(detector_id):
    for detector in default_detectors():
        if detector.DETECTOR_ID == detector_id:
            return detector
    raise KeyError(detector_id)


def run_single_detector(detector_id, assessment):
    """Run the whole pipeline with only ONE detector. Returns {asset_id: finding}."""
    result = run_assessment(assessment, detectors=[get_detector(detector_id)])
    assert result["status"] == "COMPLETED", result["findings"][0].get("errors")

    findings_by_asset = {}
    for finding in result["findings"]:
        findings_by_asset[finding["asset_id"]] = finding
    return findings_by_asset


def assets_with_status(findings_by_asset, status):
    """The set of asset ids whose finding has this status."""
    asset_ids = set()
    for asset_id, finding in findings_by_asset.items():
        if finding["status"] == status:
            asset_ids.add(asset_id)
    return asset_ids


class DetectorSpy:
    """Wraps a detector and counts how many times it is asked to evaluate."""

    def __init__(self, real_detector):
        self.real_detector = real_detector
        self.times_called = 0

    def __getattr__(self, name):
        return getattr(self.real_detector, name)

    def evaluate(self, assessment, context):
        self.times_called = self.times_called + 1
        return self.real_detector.evaluate(assessment, context)
