"""CTRL-IAM-003: enabled accounts must not sit idle."""
from engine.detectors.base_detector import BaseDetector, excluded, fail, ok, out, unevaluable
from engine.timestamp import days_between, parse_timestamp

# An enabled account idle for more than this many days is a risk (for example a leaver).
INACTIVITY_DAYS = 90


class InactiveAccountDetector(BaseDetector):
    DETECTOR_ID = "DET-INACTIVE-ACCT"
    CONTROL_ID = "CTRL-IAM-003"
    BLOCK = "identity"
    LIST = "accounts"
    NOUN = "enabled accounts"

    def classify(self, record, context):
        account_name = record.get("user_id", record["record_id"])

        account_type = record.get("account_type")
        if account_type is None:
            return unevaluable(f"{account_name}: account_type missing")

        if account_type in ("service", "seasonal", "break_glass"):
            return excluded("service, seasonal and break-glass accounts are exempt through account type")

        if account_type != "human":
            return out()

        account_status = record.get("account_status")
        if account_status is None:
            return unevaluable(f"{account_name}: account_status missing")

        if account_status == "disabled":
            return out()

        last_login = record.get("last_login")
        creation_date = record.get("account_creation_date")
        reference_date = last_login or creation_date

        if not reference_date:
            return unevaluable(f"{account_name}: no last_login or creation date")

        days_idle = days_between(context.collected_at, parse_timestamp(reference_date))

        if days_idle > INACTIVITY_DAYS:
            return fail(f"{account_name} idle {days_idle} days")
        return ok()
