"""CTRL-NET-001: administrative ports must not be open to the whole internet."""
from engine.detectors.base_detector import BaseDetector, fail, ok, out, unevaluable

ADMIN_PORTS = (22, 3389)                     # SSH and RDP
BROAD_CIDRS = ("0.0.0.0/0", "::/0")          # "any address on the internet"
# These put a control (and MFA) in front of the service, so broad exposure can be acceptable.
CONTROLLED_MECHANISMS = ("vpn", "ztna", "reverse_proxy", "bastion")


class RemoteAccessDetector(BaseDetector):
    DETECTOR_ID = "DET-REMOTE-ACCESS"
    CONTROL_ID = "CTRL-NET-001"
    BLOCK = "access_control"
    LIST = "rules"
    NOUN = "administrative firewall rules"
    EMPTY_SCOPE_PASS = True

    def classify(self, record, context):

        rule_name = record.get("firewall_rule", record["record_id"])

        port = record.get("port")
        if port is None:
            return unevaluable(f"{rule_name}: port missing")

        if port not in ADMIN_PORTS:
            return out()

        source_cidr = record.get("source_cidr")
        if source_cidr is None:
            return unevaluable(f"{rule_name}: source_cidr missing")

        if source_cidr not in BROAD_CIDRS:
            return ok()

        access_mechanism = record.get("access_mechanism")
        mfa_required = record.get("mfa_required")

        if access_mechanism is None:
            return unevaluable(f"{rule_name}: access_mechanism missing")

        if access_mechanism == "direct":
            return fail(f"{rule_name} exposes port {port} to {source_cidr} directly")

        if access_mechanism in CONTROLLED_MECHANISMS and mfa_required is True:
            return ok()

        if mfa_required is False:
            return fail(f"{rule_name} exposes port {port} to {source_cidr} via {access_mechanism} without MFA")

        return unevaluable(f"{rule_name}: mfa_required missing")
