"""CTRL-CLD-001: storage holding sensitive data must not be public."""
from engine.detectors.base_detector import BaseDetector, fail, ok, unevaluable, unknown


class CloudStorageExposureDetector(BaseDetector):
    DETECTOR_ID = "DET-CLOUD-EXPOSURE"
    CONTROL_ID = "CTRL-CLD-001"
    BLOCK = "cloud_storage"
    LIST = "buckets"
    NOUN = "storage resources"

    def classify(self, record, context):
        storage_name = record.get("storage_id", record["record_id"])
        asset_id = record["asset_id"]

        public_access_status = record.get("public_access_status")
        dlp_findings = record.get("dlp_findings")   # None = no scan, [] = scanned and clean

        if unknown(public_access_status):
            return unevaluable(f"{storage_name}: public access status unknown")

        if public_access_status == "private":
            return ok()

        # A DLP hit counts even if the asset's declared tier says "not sensitive".
        sensitive_types_found = []
        if dlp_findings:
            sensitive_types_found = list(dlp_findings)

        asset_is_sensitive = context.is_sensitive(asset_id)

        if asset_is_sensitive or len(sensitive_types_found) > 0:
            if len(sensitive_types_found) > 0:
                what_is_exposed = ", ".join(sensitive_types_found)
            else:
                what_is_exposed = f"{context.tier(asset_id)} data"
            return fail(f"{storage_name} is public and holds sensitive data ({what_is_exposed})")

        if dlp_findings is None:
            return unevaluable(f"{storage_name}: public with no DLP scan")

        return ok(f"{storage_name} is public with no sensitive data found")
