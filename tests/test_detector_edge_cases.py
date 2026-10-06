"""Gate 2: tricky situations for individual detectors. Each test changes ONE thing in a sample."""
from tests.helpers import run_single_detector


# --- Identity ---------------------------------------------------------------

def test_confirmed_mfa_failure_wins_over_unknown(scenario):
    assessment = scenario("secure_state")
    accounts = assessment["evidence"]["identity"]["accounts"]
    accounts[0]["mfa_enforcement_status"] = "not_enforced"
    accounts[1]["mfa_enrollment_status"] = "unknown"
    accounts[1]["mfa_enforcement_status"] = None

    finding = run_single_detector("DET-MFA", assessment)["AST-IDP-001"]

    assert finding["status"] == "FAIL"
    assert "could not be evaluated" in finding["description"]


def test_never_logged_in_account_is_judged_from_creation_date(scenario):
    assessment = scenario("secure_state")
    account = assessment["evidence"]["identity"]["accounts"][49]
    account["last_login"] = None
    account["account_creation_date"] = "2026-03-01"

    finding = run_single_detector("DET-INACTIVE-ACCT", assessment)["AST-IDP-001"]

    assert finding["status"] == "FAIL"


def test_short_usage_window_is_insufficient_not_fail(scenario):
    assessment = scenario("secure_state")
    assessment["evidence"]["identity"]["accounts"][10]["usage_period"] = 30

    finding = run_single_detector("DET-EXCESS-PRIV", assessment)["AST-IDP-001"]

    assert finding["status"] == "INSUFFICIENT"


def test_federated_only_policy_is_excluded_not_failed(scenario):
    assessment = scenario("insecure_state")
    assessment["evidence"]["identity"]["password_policies"].pop(0)    # leaves only the federated policy

    finding = run_single_detector("DET-PASSWORD", assessment)["AST-IDP-001"]

    assert finding["status"] == "PASS"
    assert "Excluded by documented exception" in finding["description"]


# --- Data protection --------------------------------------------------------

def test_tier1_store_needs_customer_managed_key(scenario):
    assessment = scenario("secure_state")
    assessment["evidence"]["data_protection"]["at_rest"][0]["key_management"] = "provider_managed"

    finding = run_single_detector("DET-ENC-REST", assessment)["AST-DB-001"]

    assert finding["status"] == "FAIL"


def test_tier2_store_may_use_provider_key(scenario):
    findings = run_single_detector("DET-ENC-REST", scenario("secure_state"))

    assert findings["AST-STO-002"]["status"] == "PASS"


def test_weak_cipher_fails(scenario):
    assessment = scenario("secure_state")
    assessment["evidence"]["data_protection"]["in_transit"][0]["cipher"] = "TLS_RSA_WITH_RC4_128_SHA"

    finding = run_single_detector("DET-ENC-TRANSIT", assessment)["AST-APP-001"]

    assert finding["status"] == "FAIL"


# --- Endpoint ---------------------------------------------------------------

def test_accepted_risk_does_not_turn_fail_into_pass(scenario):
    assessment = scenario("insecure_state")
    assessment["evidence"]["vulnerability"]["software"][1]["risk_acceptance_status"] = "accepted"

    finding = run_single_detector("DET-VULN-SW", assessment)["AST-SRV-001"]

    assert finding["status"] == "FAIL"
    assert "risk accepted" in finding["description"]


def test_high_cvss_on_supported_software_fails(scenario):
    assessment = scenario("secure_state")
    software = assessment["evidence"]["vulnerability"]["software"][0]
    software["cve"] = "CVE-2026-0003"
    software["cvss"] = 8.1

    finding = run_single_detector("DET-VULN-SW", assessment)["AST-APP-001"]

    assert finding["status"] == "FAIL"


def test_ephemeral_devices_are_excluded(scenario):
    # The secure sample contains two ephemeral virtual desktops with no protection installed.
    findings = run_single_detector("DET-ENDPOINT", scenario("secure_state"))

    assert findings["AST-END-001"]["status"] == "PASS"


# --- Exposure ---------------------------------------------------------------

def test_public_bucket_without_dlp_scan_is_insufficient(scenario):
    assessment = scenario("secure_state")
    assessment["evidence"]["cloud_storage"]["buckets"][2]["dlp_findings"] = None

    finding = run_single_detector("DET-CLOUD-EXPOSURE", assessment)["AST-STO-003"]

    assert finding["status"] == "INSUFFICIENT"


def test_public_non_sensitive_bucket_passes_with_note(scenario):
    finding = run_single_detector("DET-CLOUD-EXPOSURE", scenario("secure_state"))["AST-STO-003"]

    assert finding["status"] == "PASS"
    assert "no sensitive data found" in finding["description"]


def test_dlp_hit_overrides_non_sensitive_tier(scenario):
    assessment = scenario("secure_state")
    assessment["evidence"]["cloud_storage"]["buckets"][2]["dlp_findings"] = ["customer_pii"]

    finding = run_single_detector("DET-CLOUD-EXPOSURE", assessment)["AST-STO-003"]

    assert finding["status"] == "FAIL"


def test_zero_trust_rule_without_mfa_fails(scenario):
    assessment = scenario("secure_state")
    assessment["evidence"]["access_control"]["rules"][1]["mfa_required"] = False

    finding = run_single_detector("DET-REMOTE-ACCESS", assessment)["AST-NET-001"]

    assert finding["status"] == "FAIL"


def test_rule_list_without_admin_ports_passes(scenario):
    assessment = scenario("secure_state")
    all_rules = assessment["evidence"]["access_control"]["rules"]
    assessment["evidence"]["access_control"]["rules"] = all_rules[2:]   # keeps only the port 443 rule

    finding = run_single_detector("DET-REMOTE-ACCESS", assessment)["AST-NET-001"]

    assert finding["status"] == "PASS"


# --- Resilience -------------------------------------------------------------

def test_stateless_assets_are_excluded_and_pass(scenario):
    findings = run_single_detector("DET-BACKUP", scenario("secure_state"))

    for asset_id in ("AST-APP-001", "AST-STO-003"):
        assert findings[asset_id]["status"] == "PASS"
        assert "Excluded" in findings[asset_id]["description"]


def test_old_backup_fails(scenario):
    assessment = scenario("secure_state")
    assessment["evidence"]["backup"]["coverage"][0]["last_backup_timestamp"] = "2026-09-30T09:00:00Z"

    finding = run_single_detector("DET-BACKUP", assessment)["AST-DB-001"]

    assert finding["status"] == "FAIL"


def test_non_required_log_source_is_ignored(scenario):
    assessment = scenario("secure_state")
    sandbox_source = assessment["evidence"]["logging"]["sources"][6]    # dev-sandbox, not required
    sandbox_source["source_status"] = "inactive"
    sandbox_source["last_received_timestamp"] = "2026-09-01T00:00:00Z"

    finding = run_single_detector("DET-LOGGING", assessment)["AST-LOG-001"]

    assert finding["status"] == "PASS"
