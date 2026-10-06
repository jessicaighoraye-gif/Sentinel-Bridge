"""CTRL-LOG-001: required log sources must be active, audited and reporting normally."""
from engine.detectors.base_detector import BaseDetector, fail, ok, out, unevaluable, unknown
from engine.timestamp import hours_between, parse_timestamp

# A required source silent for longer than this is treated as a logging gap.
MAX_SILENCE_HOURS = 24
# Ingesting less than half the expected volume suggests logs are being dropped.
MIN_INGESTION_RATIO = 0.5


class LoggingMonitoringDetector(BaseDetector):
    DETECTOR_ID = "DET-LOGGING"
    CONTROL_ID = "CTRL-LOG-001"
    BLOCK = "logging"
    LIST = "sources"
    NOUN = "required log sources"

    def classify(self, record, context):
        source_name = record.get("log_source", record["record_id"])

        required_source = record.get("required_source")
        if required_source is None:
            return unevaluable(f"{source_name}: required_source missing")

        if not required_source:
            return out()

        last_received = record.get("last_received_timestamp")
        expected_rate = record.get("expected_ingestion_rate")
        observed_rate = record.get("observed_ingestion_rate")
        source_status = record.get("source_status")
        audit_configuration = record.get("audit_configuration")

        problems = []

        if source_status == "inactive":
            problems.append("source inactive")

        if audit_configuration == "disabled":
            problems.append("auditing disabled")

        if last_received is not None:
            hours_silent = hours_between(context.collected_at, parse_timestamp(last_received))
            if hours_silent > MAX_SILENCE_HOURS:
                problems.append(f"silent {hours_silent:.0f} hours")

        if expected_rate and observed_rate is not None:
            ingestion_ratio = observed_rate / expected_rate
            if ingestion_ratio < MIN_INGESTION_RATIO:
                problems.append("ingestion below expected rate")

        if len(problems) > 0:
            return fail(f"{source_name}: " + ", ".join(problems))

        if unknown(source_status) or unknown(audit_configuration):
            return unevaluable(f"{source_name}: logging evidence incomplete")
        if last_received is None or expected_rate is None or observed_rate is None:
            return unevaluable(f"{source_name}: logging evidence incomplete")

        return ok()
