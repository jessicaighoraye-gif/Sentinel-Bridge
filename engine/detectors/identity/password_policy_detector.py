"""CTRL-IAM-004: the local password policy must meet the company baseline."""
from engine.detectors.base_detector import BaseDetector, excluded, fail, ok, unevaluable

MIN_PASSWORD_LENGTH = 12
COMPLEXITY_REQUIRED = True
MAX_PASSWORD_AGE_DAYS = 365   # 0 means passwords never expire
MAX_LOCKOUT_THRESHOLD = 10    # 0 means there is no lockout at all


class PasswordPolicyDetector(BaseDetector):
    DETECTOR_ID = "DET-PASSWORD"
    CONTROL_ID = "CTRL-IAM-004"
    BLOCK = "identity"
    LIST = "password_policies"
    NOUN = "local password policies"

    def classify(self, record, context):
        policy_name = record.get("tenant_or_domain", record["record_id"])

        authentication_source = record.get("authentication_source")
        if authentication_source is None:
            return unevaluable(f"{policy_name}: authentication_source missing")

        if authentication_source == "federated":
            # A federated identity uses the partner's password rules, not ours.
            return excluded("federated identities are not evaluated against local password rules")

        minimum_length = record.get("minimum_password_length")
        complexity_required = record.get("complexity_requirements")
        maximum_age_days = record.get("maximum_password_age")
        lockout_settings = record.get("lockout_configuration")
        if lockout_settings is None:
            lockout_threshold = None
        else:
            lockout_threshold = lockout_settings.get("threshold")

        problems = []

        if minimum_length is not None and minimum_length < MIN_PASSWORD_LENGTH:
            problems.append(f"minimum length {minimum_length}")

        if COMPLEXITY_REQUIRED and complexity_required is False:
            problems.append("complexity not required")

        if maximum_age_days is not None:
            if maximum_age_days == 0:
                problems.append("passwords never expire")
            elif maximum_age_days > MAX_PASSWORD_AGE_DAYS:
                problems.append(f"maximum age {maximum_age_days} days")

        if lockout_threshold is not None:
            if lockout_threshold == 0:
                problems.append("no account lockout")
            elif lockout_threshold > MAX_LOCKOUT_THRESHOLD:
                problems.append(f"lockout threshold {lockout_threshold}")

        if len(problems) > 0:
            return fail(f"{policy_name}: " + ", ".join(problems))

        if minimum_length is None or complexity_required is None:
            return unevaluable(f"{policy_name}: policy fields missing")
        if maximum_age_days is None or lockout_threshold is None:
            return unevaluable(f"{policy_name}: policy fields missing")

        return ok()
