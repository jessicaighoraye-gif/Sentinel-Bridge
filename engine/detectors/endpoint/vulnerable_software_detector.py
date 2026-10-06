"""CTRL-END-001: software must be vendor-supported and free of severe known vulnerabilities."""
from engine.detectors.base_detector import BaseDetector, fail, ok, unevaluable, unknown

# CVSS 7.0 and above is rated High or Critical, so it must be fixed.
CVSS_FAIL_THRESHOLD = 7.0


class VulnerableSoftwareDetector(BaseDetector):
    DETECTOR_ID = "DET-VULN-SW"
    CONTROL_ID = "CTRL-END-001"
    BLOCK = "vulnerability"
    LIST = "software"
    NOUN = "software items"

    def classify(self, record, context):

        software_name = record.get("software_name", "?")
        software_version = record.get("version", "")
        software_label = f"{software_name} {software_version}".strip()

        support_status = record.get("vendor_support_status")
        cve = record.get("cve")
        cvss_score = record.get("cvss")

        problems = []

        if support_status == "end_of_life":
            problems.append("vendor support ended")

        if cve and cvss_score is not None:
            if cvss_score >= CVSS_FAIL_THRESHOLD:
                problems.append(f"{cve} CVSS {cvss_score}")

        if len(problems) > 0:
            # Accepting a risk does not make the problem go away, so it is still a FAIL.
            # The acceptance is only noted, because treatment is a management decision.
            risk_note = ""
            if record.get("risk_acceptance_status") == "accepted":
                risk_note = " (risk accepted, treatment decided in Phase 2)"
            return fail(f"{software_label} on {record['asset_id']}: " + ", ".join(problems) + risk_note)

        if unknown(support_status):
            return unevaluable(f"{software_label}: support status or CVSS missing")
        if cve and cvss_score is None:
            return unevaluable(f"{software_label}: support status or CVSS missing")

        return ok()
