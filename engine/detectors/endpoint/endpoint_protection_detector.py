"""CTRL-END-002: in-scope devices must run active, up-to-date endpoint protection."""
from engine.detectors.base_detector import BaseDetector, excluded, fail, ok, unevaluable, unknown


class EndpointProtectionDetector(BaseDetector):
    DETECTOR_ID = "DET-ENDPOINT"
    CONTROL_ID = "CTRL-END-002"
    BLOCK = "endpoint"
    LIST = "devices"
    NOUN = "devices"

    def classify(self, record, context):
        device_name = record.get("hostname", record["record_id"])

        scope_status = record.get("endpoint_scope_status")
        if scope_status is None:
            return unevaluable(f"{device_name}: endpoint_scope_status missing")

        if scope_status == "ephemeral" or scope_status == "out_of_scope":
            # Short-lived desktops are rebuilt from a clean image, so they are not checked.
            return excluded(f"{scope_status} devices are outside endpoint-protection scope")

        installation_status = record.get("installation_status")
        protection_status = record.get("protection_status")
        definition_status = record.get("definition_update_status")

        problems = []

        if installation_status == "not_installed":
            problems.append("agent not installed")

        if protection_status == "inactive":
            problems.append("protection inactive")

        if definition_status == "outdated":
            problems.append("definitions outdated")

        if len(problems) > 0:
            return fail(f"{device_name}: " + ", ".join(problems))

        if unknown(installation_status) or unknown(protection_status) or unknown(definition_status):
            return unevaluable(f"{device_name}: protection status unknown")

        return ok()
