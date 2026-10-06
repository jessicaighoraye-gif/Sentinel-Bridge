"""CTRL-BCP-001: stateful assets need recent, retained and (for tier 1) tamper-proof backups."""
from engine.detectors.base_detector import BaseDetector, excluded, fail, ok, unevaluable, unknown
from engine.timestamp import hours_between, parse_timestamp

# A backup older than this means recent changes would be lost in a recovery.
BACKUP_MAX_AGE_HOURS = 24
MIN_RETENTION_DAYS = 30
# Immutable backups survive ransomware that deletes ordinary backups.
IMMUTABILITY_REQUIRED_TIERS = ("tier_1",)


class BackupRecoveryDetector(BaseDetector):
    DETECTOR_ID = "DET-BACKUP"
    CONTROL_ID = "CTRL-BCP-001"
    BLOCK = "backup"
    LIST = "coverage"
    NOUN = "resources needing backup"

    def classify(self, record, context):
        resource_name = record.get("resource_id", record["record_id"])

        statefulness = record.get("statefulness")
        if unknown(statefulness):
            return unevaluable(f"{resource_name}: statefulness unknown")

        if statefulness == "stateless":
            return excluded("stateless")

        backup_policy = record.get("backup_policy")
        last_backup_status = record.get("last_backup_status")
        last_backup_time = record.get("last_backup_timestamp")
        retention_days = record.get("retention")
        immutability_status = record.get("immutability_status")
        data_tier = context.tier(record["asset_id"])

        problems = []

        if backup_policy == "none":
            problems.append("no backup policy")

        if last_backup_status == "failed":
            problems.append("last backup failed")

        if last_backup_time is not None:
            backup_age_hours = hours_between(context.collected_at, parse_timestamp(last_backup_time))
            if backup_age_hours > BACKUP_MAX_AGE_HOURS:
                if backup_age_hours >= 48:
                    problems.append(f"last backup {backup_age_hours / 24:.0f} days old")
                else:
                    problems.append(f"last backup {backup_age_hours:.0f} hours old")

        if retention_days is not None and retention_days < MIN_RETENTION_DAYS:
            problems.append(f"retention {retention_days} days")

        if data_tier in IMMUTABILITY_REQUIRED_TIERS and immutability_status == "unprotected":
            problems.append("backups not immutable")

        if len(problems) > 0:
            return fail(f"{resource_name}: " + ", ".join(problems))

        if backup_policy is None or unknown(last_backup_status) or unknown(immutability_status):
            return unevaluable(f"{resource_name}: backup evidence incomplete")
        if last_backup_time is None or retention_days is None:
            return unevaluable(f"{resource_name}: backup evidence incomplete")

        return ok()
