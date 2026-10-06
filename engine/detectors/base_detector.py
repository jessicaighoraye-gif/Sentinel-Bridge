"""Shared building blocks for the 12 detectors.

HOW A DETECTOR WORKS (the same for all 12)
  1. The detector looks at every evidence record that belongs to one asset.
  2. classify() gives each record a Verdict:
        ok()           the record meets the requirement           (OK)
        fail(reason)   the evidence shows the requirement is not met  (FAIL)
        excluded(why)  a documented exception removes the record      (EXCLUDED)
        unevaluable(why) the evidence is missing or unknown           (UNEVALUABLE)
        out()          the record is not in this control's scope
  3. _combine_verdicts() turns the verdicts for one asset into ONE result:
        FAIL > INSUFFICIENT > PASS
     A confirmed failure always wins. Missing evidence is never a failure.
"""
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import yaml

from engine.timestamp import parse_timestamp
from engine.validators.input_validator import ROOT

# Status of one finding (what the engine reports for one asset)
PASS = "PASS"
FAIL = "FAIL"
INSUFFICIENT = "INSUFFICIENT"

# Verdict of one evidence record (what classify() returns)
R_PASS = "PASS"
R_FAIL = "FAIL"
R_UNEVALUABLE = "UNEVALUABLE"
R_EXCLUDED = "EXCLUDED"
R_OUT = "OUT_OF_SCOPE"

# Findings that pass or are insufficient list at most this many evidence records.
MAX_REFS_NON_FAIL = 10
# A failing finding describes at most this many individual problems.
MAX_FAIL_REASONS_SHOWN = 5
MAX_UNEVALUABLE_REASONS_SHOWN = 3


def unknown(value):
    """True when evidence says nothing useful: the field is missing or says 'unknown'."""
    return value is None or value == "unknown"


@dataclass
class Verdict:
    """The outcome for ONE evidence record."""
    kind: str
    reason: str = ""
    note: str = ""


def ok(note=""):
    return Verdict(R_PASS, note=note)


def fail(reason):
    return Verdict(R_FAIL, reason)


def unevaluable(reason):
    return Verdict(R_UNEVALUABLE, reason)


def excluded(reason):
    return Verdict(R_EXCLUDED, reason)


def out():
    return Verdict(R_OUT)


@dataclass
class AssetResult:
    """The outcome for ONE asset. finding_generator turns this into a finding."""
    asset_id: str
    status: str
    severity: str
    evidence_ref: list = field(default_factory=list)
    description: str = ""


# ---------------------------------------------------------------------------
# Company facts (assets, data tiers, controls) are read once from the YAML files.
# ---------------------------------------------------------------------------
_cached_company_facts = None


def _read_yaml(relative_path):
    full_path = ROOT / relative_path
    return yaml.safe_load(full_path.read_text(encoding="utf-8"))


def _company():
    global _cached_company_facts
    if _cached_company_facts is not None:
        return _cached_company_facts

    assets_by_id = {}
    for asset in _read_yaml("company/asset_inventory.yaml")["assets"]:
        assets_by_id[asset["asset_id"]] = asset

    sensitive_tiers = set()
    tiers = _read_yaml("company/data_classification.yaml")["tiers"]
    for tier_name, tier in tiers.items():
        if tier["sensitive"]:
            sensitive_tiers.add(tier_name)

    controls_by_id = {}
    for control in _read_yaml("controls/security_controls.yaml")["controls"]:
        controls_by_id[control["control_id"]] = control

    _cached_company_facts = {
        "assets": assets_by_id,
        "sensitive_tiers": frozenset(sensitive_tiers),
        "controls": controls_by_id,
    }
    return _cached_company_facts


@dataclass(frozen=True)
class Context:
    """What every detector needs to know besides the record itself.

    collected_at is the moment the evidence was collected. All time maths
    ("idle for 90 days", "backup older than 24 hours") is measured from it,
    not from today's date, so results never change from one day to the next.
    """
    assets: dict
    sensitive_tiers: frozenset
    collected_at: datetime

    @classmethod
    def build(cls, collected_at):
        company_facts = _company()
        return cls(company_facts["assets"], company_facts["sensitive_tiers"], parse_timestamp(collected_at))

    def tier(self, asset_id):
        """The data tier of an asset, for example 'tier_1'. Tiers are declared only in the asset inventory."""
        return self.assets[asset_id]["data_classification"]

    def is_sensitive(self, asset_id):
        return self.tier(asset_id) in self.sensitive_tiers


class BaseDetector:
    """Parent class of all 12 detectors. A child sets the five names below and writes classify()."""

    DETECTOR_ID = ""
    CONTROL_ID = ""
    BLOCK = ""       # evidence block, for example "identity"
    LIST = ""        # list of records inside that block, for example "accounts"
    NOUN = "records"  # how findings name the records, for example "privileged accounts"

    # CTRL-NET-001 only: a rule list that contains no administrative-port rule is a PASS,
    # because the evidence shows nothing is exposed.
    EMPTY_SCOPE_PASS = False

    def __init__(self):
        self.config = _company()["controls"][self.CONTROL_ID]
        assert self.config["detector_id"] == self.DETECTOR_ID, f"{self.CONTROL_ID} detector id mismatch"
        self.severity_on_fail = self.config["severity_on_fail"]

    # ----- each detector writes this -----
    def classify(self, record, context):
        """Return a Verdict for ONE evidence record."""
        raise NotImplementedError

    # ----- shared logic -----
    def applicable_assets(self, context):
        """The assets this control must be checked on, in inventory order."""
        categories = self.config["scope"]["applies_to"]

        asset_ids = []
        for asset_id, asset in context.assets.items():
            if asset["category"] in categories:
                asset_ids.append(asset_id)

        # Encryption controls only matter for assets that hold sensitive data.
        if self.CONTROL_ID in ("CTRL-DATA-001", "CTRL-DATA-002"):
            sensitive_asset_ids = []
            for asset_id in asset_ids:
                if context.is_sensitive(asset_id):
                    sensitive_asset_ids.append(asset_id)
            asset_ids = sensitive_asset_ids

        return asset_ids

    def evaluate(self, assessment, context):
        """Return one AssetResult for every asset this control applies to."""
        evidence = assessment.get("evidence", {})
        block = evidence.get(self.BLOCK, {})
        all_records = block.get(self.LIST, [])

        results = []
        for asset_id in self.applicable_assets(context):
            judged_records = []
            for record in all_records:
                if record.get("asset_id") == asset_id:
                    verdict = self.classify(record, context)
                    judged_records.append((record, verdict))
            results.append(self._combine_verdicts(asset_id, judged_records))
        return results

    def _evidence_reference(self, record):
        """Text that points back at a record, for example identity:ACC-0003."""
        return f"{self.BLOCK}:{record['record_id']}"

    def _evidence_references(self, judged_records, limit=None):
        references = []
        for record, verdict in judged_records:
            references.append(self._evidence_reference(record))
        if limit is not None:
            references = references[:limit]
        return references

    def _combine_verdicts(self, asset_id, judged_records):
        """Turn the verdicts of one asset's records into one AssetResult.

        Order of importance: FAIL, then INSUFFICIENT, then PASS.
        """
        failed = []
        unevaluable_records = []
        passed = []
        excluded_records = []
        for record, verdict in judged_records:
            if verdict.kind == R_FAIL:
                failed.append((record, verdict))
            elif verdict.kind == R_UNEVALUABLE:
                unevaluable_records.append((record, verdict))
            elif verdict.kind == R_PASS:
                passed.append((record, verdict))
            elif verdict.kind == R_EXCLUDED:
                excluded_records.append((record, verdict))
            # R_OUT records are simply ignored.

        in_scope_count = len(failed) + len(unevaluable_records) + len(passed)

        # A confirmed failure always wins, even if other records are unclear.
        if len(failed) > 0:
            return self._failing_result(asset_id, failed, unevaluable_records, in_scope_count)

        # Missing evidence is never a failure: it is INSUFFICIENT.
        if len(unevaluable_records) > 0:
            return self._insufficient_result(asset_id, unevaluable_records, in_scope_count)

        if len(passed) > 0:
            return self._passing_result(asset_id, passed)

        # Every record was removed by a documented exception (for example stateless assets).
        if len(excluded_records) > 0:
            return self._excluded_result(asset_id, excluded_records)

        # Records exist but none is in scope, and the control treats that as a pass.
        if self.EMPTY_SCOPE_PASS and len(judged_records) > 0:
            return self._nothing_exposed_result(asset_id, judged_records)

        return self._no_evidence_result(asset_id, judged_records)

    def _failing_result(self, asset_id, failed, unevaluable_records, in_scope_count):
        reasons = []
        for record, verdict in failed[:MAX_FAIL_REASONS_SHOWN]:
            reasons.append(verdict.reason)

        more_text = ""
        if len(failed) > MAX_FAIL_REASONS_SHOWN:
            more_text = f" (and {len(failed) - MAX_FAIL_REASONS_SHOWN} more)"

        other_text = ""
        if len(unevaluable_records) > 0:
            other_text = f" {len(unevaluable_records)} other record(s) could not be evaluated."

        description = (
            f"{len(failed)} of {in_scope_count} in-scope {self.NOUN} fail: "
            + "; ".join(reasons) + more_text + "." + other_text
        )
        return AssetResult(asset_id, FAIL, self.severity_on_fail, self._evidence_references(failed), description)

    def _insufficient_result(self, asset_id, unevaluable_records, in_scope_count):
        reasons = []
        for record, verdict in unevaluable_records[:MAX_UNEVALUABLE_REASONS_SHOWN]:
            reasons.append(verdict.reason)

        description = (
            f"{len(unevaluable_records)} of {in_scope_count} in-scope {self.NOUN} "
            f"cannot be evaluated: " + "; ".join(reasons) + "."
        )
        references = self._evidence_references(unevaluable_records, MAX_REFS_NON_FAIL)
        return AssetResult(asset_id, INSUFFICIENT, "none", references, description)

    def _passing_result(self, asset_id, passed):
        # A passing record may carry a note, for example "public with no sensitive data found".
        notes = set()
        for record, verdict in passed:
            if verdict.note:
                notes.add(verdict.note)

        description = f"All {len(passed)} in-scope {self.NOUN} meet the requirement."
        if len(notes) > 0:
            description = description + " " + "; ".join(sorted(notes)) + "."

        references = self._evidence_references(passed, MAX_REFS_NON_FAIL)
        return AssetResult(asset_id, PASS, "none", references, description)

    def _excluded_result(self, asset_id, excluded_records):
        reasons = set()
        for record, verdict in excluded_records:
            reasons.add(verdict.reason)

        description = "Excluded by documented exception: " + "; ".join(sorted(reasons)) + "."
        references = self._evidence_references(excluded_records, MAX_REFS_NON_FAIL)
        return AssetResult(asset_id, PASS, "none", references, description)

    def _nothing_exposed_result(self, asset_id, judged_records):
        description = f"None of the {len(judged_records)} {self.NOUN} exposes the controlled service broadly."
        references = self._evidence_references(judged_records, MAX_REFS_NON_FAIL)
        return AssetResult(asset_id, PASS, "none", references, description)

    def _no_evidence_result(self, asset_id, judged_records):
        if len(judged_records) > 0:
            description = f"No in-scope {self.NOUN} found for this asset."
        else:
            description = f"No {self.BLOCK} evidence was supplied for this asset."
        return AssetResult(asset_id, INSUFFICIENT, "none", [], description)
