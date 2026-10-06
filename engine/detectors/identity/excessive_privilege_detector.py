"""CTRL-IAM-002: users should hold only the permissions they use or are approved for."""
from engine.detectors.base_detector import BaseDetector, excluded, fail, ok, out, unevaluable

# Unused permissions can only be judged after watching usage for this many days.
USAGE_WINDOW_DAYS = 90
# Any permission that is neither used nor approved counts as excess.
MAX_EXCESS_PERMISSIONS = 0


class ExcessivePrivilegeDetector(BaseDetector):
    DETECTOR_ID = "DET-EXCESS-PRIV"
    CONTROL_ID = "CTRL-IAM-002"
    BLOCK = "identity"
    LIST = "accounts"
    NOUN = "user accounts"

    def classify(self, record, context):
        account_name = record.get("user_id", record["record_id"])

        account_type = record.get("account_type")
        if account_type is None:
            return unevaluable(f"{account_name}: account_type missing")

        if account_type == "service" or account_type == "break_glass":
            return excluded("service and break-glass accounts are handled by separate rules")

        if account_type != "human":
            return out()

        assigned_permissions = record.get("assigned_permissions")
        used_permissions = record.get("used_permissions")
        approved_permissions = record.get("resource_scope")
        days_observed = record.get("usage_period")

        if assigned_permissions is None or used_permissions is None:
            return unevaluable(f"{account_name}: permission or usage evidence missing")
        if approved_permissions is None or days_observed is None:
            return unevaluable(f"{account_name}: permission or usage evidence missing")

        if days_observed < USAGE_WINDOW_DAYS:
            return unevaluable(f"{account_name}: only {days_observed} days of usage observed")

        excess_permissions = set(assigned_permissions) - set(used_permissions) - set(approved_permissions)
        excess_permissions = sorted(excess_permissions)

        if len(excess_permissions) > MAX_EXCESS_PERMISSIONS:
            return fail(f"{account_name} holds unused permissions {', '.join(excess_permissions)}")
        return ok()
