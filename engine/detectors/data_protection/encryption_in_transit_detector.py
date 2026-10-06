"""CTRL-DATA-002: sensitive data must travel over modern TLS (or protected internal links)."""
from engine.detectors.base_detector import BaseDetector, fail, ok, unevaluable

MIN_TLS_VERSION = 1.2
CLEARTEXT_PROTOCOLS = ("http", "ftp", "telnet")
# Cipher names containing any of these are known to be broken.
WEAK_CIPHER_MARKERS = ("RC4", "3DES", "NULL", "EXPORT")


class EncryptionInTransitDetector(BaseDetector):
    DETECTOR_ID = "DET-ENC-TRANSIT"
    CONTROL_ID = "CTRL-DATA-002"
    BLOCK = "data_protection"
    LIST = "in_transit"
    NOUN = "data flows"

    def classify(self, record, context):
        source = record.get("source", "?")
        destination = record.get("destination", "?")
        flow_name = f"{source} to {destination}"

        protocol = record.get("protocol")
        tls_version = record.get("tls_version")
        cipher = record.get("cipher")
        flow_scope = record.get("flow_scope")
        protection_mechanism = record.get("protection_mechanism")

        problems = []

        if protocol in CLEARTEXT_PROTOCOLS:
            problems.append(f"cleartext {protocol}")

        if tls_version is not None and float(tls_version) < MIN_TLS_VERSION:
            problems.append(f"TLS {tls_version}")

        if cipher is not None:
            for weak_marker in WEAK_CIPHER_MARKERS:
                if weak_marker in cipher.upper():
                    problems.append(f"weak cipher {cipher}")
                    break

        if flow_scope == "internal" and protection_mechanism == "none":
            problems.append("internal flow unprotected")

        if len(problems) > 0:
            return fail(f"{flow_name}: " + ", ".join(problems))

        required_values = [
            record.get("source"), record.get("destination"), record.get("port"),
            protocol, flow_scope, protection_mechanism,
        ]
        for value in required_values:
            if value is None:
                return unevaluable(f"{flow_name}: transport evidence incomplete")

        if protocol == "other":
            return unevaluable(f"{flow_name}: transport evidence incomplete")

        if protocol == "https" or protocol == "tls":
            if tls_version is None or cipher is None:
                return unevaluable(f"{flow_name}: TLS version or cipher missing")

        return ok()
