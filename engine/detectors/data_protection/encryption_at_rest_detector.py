"""CTRL-DATA-001: sensitive data stores must be encrypted, tier 1 with customer-managed keys."""
from engine.detectors.base_detector import BaseDetector, fail, ok, unevaluable, unknown

APPROVED_ALGORITHMS = ("AES-256",)
CMK_REQUIRED_TIERS = ("tier_1",)


class EncryptionAtRestDetector(BaseDetector):
    DETECTOR_ID = "DET-ENC-REST"
    CONTROL_ID = "CTRL-DATA-001"
    BLOCK = "data_protection"
    LIST = "at_rest"
    NOUN = "data stores"

    def classify(self, record, context):
        store_name = record.get("resource_id", record["record_id"])
        encryption_status = record.get("encryption_status")
        key_management = record.get("key_management")
        key_id = record.get("key_id")
        algorithm = record.get("encryption_algorithm")
        data_tier = context.tier(record["asset_id"])

        problems = []

        if encryption_status == "disabled":
            problems.append("encryption disabled")

        if encryption_status == "enabled" and algorithm is not None:
            if algorithm not in APPROVED_ALGORITHMS:
                problems.append(f"algorithm {algorithm} not approved")

        if data_tier in CMK_REQUIRED_TIERS:
            if key_management == "provider_managed" or key_management == "none":
                problems.append("no customer-managed key for tier 1 data")

        if len(problems) > 0:
            return fail(f"{store_name}: " + ", ".join(problems))

        if unknown(encryption_status) or key_management is None:
            return unevaluable(f"{store_name}: encryption evidence incomplete")
        if encryption_status == "enabled" and (key_id is None or algorithm is None):
            return unevaluable(f"{store_name}: encryption evidence incomplete")

        return ok()
