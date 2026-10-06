"""CTRL-IAM-001: privileged accounts must have MFA enrolled and enforced."""
from engine.detectors.base_detector import BaseDetector, excluded, fail, ok, out, unevaluable, unknown


class MfaDetector(BaseDetector):
    DETECTOR_ID = "DET-MFA"
    CONTROL_ID = "CTRL-IAM-001"
    BLOCK = "identity"
    LIST = "accounts"
    NOUN = "privileged accounts"

    def classify(self, record, context):
  
        account_name = record.get("user_id", record["record_id"])

        account_type = record.get("account_type")
        if account_type is None:
            return unevaluable(f"{account_name}: account_type missing")

        if account_type == "service":
            # Service accounts cannot answer an MFA prompt. They need key and certificate controls.
            return excluded("service accounts need separate key and certificate controls")

        # Break-glass accounts are privileged humans, so they ARE checked. Other types are not.
        if account_type != "human" and account_type != "break_glass":
            return out()

        privileged_status = record.get("privileged_status")
        if privileged_status is None:
            return unevaluable(f"{account_name}: privileged_status missing")

        if not privileged_status:
            return out()

        enrollment_status = record.get("mfa_enrollment_status")
        enforcement_status = record.get("mfa_enforcement_status")

        # One confirmed gap is enough to fail, even if the other field is unknown.
        if enrollment_status == "not_enrolled":
            return fail(f"{account_name} MFA not enrolled")
        if enforcement_status == "not_enforced":
            return fail(f"{account_name} MFA not enforced")

        if unknown(enrollment_status) or unknown(enforcement_status):
            return unevaluable(f"{account_name}: MFA status unknown")

        return ok()
