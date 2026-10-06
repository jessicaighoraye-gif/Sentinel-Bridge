# Remediation Plan

Prepared from the risk register and the remediation rules. Priority is inherent risk, highest first.
Verification is the detector itself: each action is complete when the detector passes on updated evidence.

Retest result: 10 of 18 remediations verified (FAIL to PASS). 8 remain open.

| # | Risk | Asset | Action | Owner | Target date | Effort | Retest |
|---|---|---|---|---|---|---|---|
| 1 | RISK-REMOTE-ACCESS-01 | AST-NET-001 Perimeter firewall and remote-access gateway | Remove the direct rule and move remote administration behind zero trust access or a VPN with MFA. | Security Lead | 2026-10-09 | low | DET-REMOTE-ACCESS -> PASS |
| 2 | RISK-CLOUD-EXPOSURE-01 | AST-STO-001 Customer documents storage | Turn on block-public-access for the affected buckets, remove public ACLs, and review access logs for earlier exposure. | Data Protection Officer | 2026-10-09 | low | DET-CLOUD-EXPOSURE -> PASS |
| 3 | RISK-MFA-01 | AST-IDP-001 Identity platform (cloud identity tenant) | Enroll the affected privileged accounts in MFA and enforce a policy that requires MFA for all privileged roles. | IT Operations Manager | 2026-10-09 | low | DET-MFA -> PASS |
| 4 | RISK-ENDPOINT-02 | AST-END-002 Remote endpoint fleet (laptops) | Reinstall the agent on the affected devices, force a definition update, and alert when a device falls out of compliance. | IT Operations Manager | 2026-11-01 | low | DET-ENDPOINT -> FAIL |
| 5 | RISK-CLOUD-EXPOSURE-02 | AST-STO-002 Finance reports storage | Turn on block-public-access for the affected buckets, remove public ACLs, and review access logs for earlier exposure. | Head of Finance | 2026-11-01 | low | DET-CLOUD-EXPOSURE -> PASS |
| 6 | RISK-ENC-REST-01 | AST-DB-001 Customer database | Enable AES-256 encryption on the customer database and move tier 1 stores to customer-managed keys in the key management service. | Head of Engineering | 2026-11-01 | medium | DET-ENC-REST -> PASS |
| 7 | RISK-ENC-TRANSIT-01 | AST-DB-001 Customer database | Disable HTTP and TLS 1.0 and 1.1 on the affected endpoints, remove weak ciphers, and require partners to support TLS 1.2 or higher. | Head of Engineering | 2026-11-01 | medium | DET-ENC-TRANSIT -> PASS |
| 8 | RISK-ENC-TRANSIT-03 | AST-SRV-001 Payment gateway server | Disable HTTP and TLS 1.0 and 1.1 on the affected endpoints, remove weak ciphers, and require partners to support TLS 1.2 or higher. | IT Operations Manager | 2026-11-01 | medium | DET-ENC-TRANSIT -> FAIL |
| 9 | RISK-EXCESS-PRIV-01 | AST-IDP-001 Identity platform (cloud identity tenant) | Remove the unused permissions the detector listed, then run a quarterly access review for privileged roles. | IT Operations Manager | 2026-11-01 | medium | DET-EXCESS-PRIV -> FAIL |
| 10 | RISK-INACTIVE-ACCT-01 | AST-IDP-001 Identity platform (cloud identity tenant) | Disable the idle accounts, tie account removal to the leaver process, and auto-disable accounts after 90 days of inactivity. | IT Operations Manager | 2026-11-01 | low | DET-INACTIVE-ACCT -> PASS |
| 11 | RISK-PASSWORD-01 | AST-IDP-001 Identity platform (cloud identity tenant) | Set minimum length to 12 or more, require complexity, set a maximum age, and lock accounts after 10 failed attempts or fewer. | IT Operations Manager | 2026-11-01 | low | DET-PASSWORD -> FAIL |
| 12 | RISK-VULN-SW-02 | AST-SRV-001 Payment gateway server | Migrate the affected servers to supported versions, patch severe CVEs, and keep an end-of-life register. | IT Operations Manager | 2026-11-01 | high | DET-VULN-SW -> FAIL |
| 13 | RISK-VULN-SW-03 | AST-SRV-002 Reconciliation server | Migrate the affected servers to supported versions, patch severe CVEs, and keep an end-of-life register. | IT Operations Manager | 2026-11-01 | high | DET-VULN-SW -> FAIL |
| 14 | RISK-ENC-REST-02 | AST-STO-001 Customer documents storage | Enable AES-256 encryption on the customer database and move tier 1 stores to customer-managed keys in the key management service. | Data Protection Officer | 2026-11-01 | medium | DET-ENC-REST -> PASS |
| 15 | RISK-LOGGING-01 | AST-LOG-001 Central security logging platform | Restore the silent log forwarder, enable database auditing, and alert when a source stops reporting. | Security Lead | 2026-11-01 | low | DET-LOGGING -> FAIL |
| 16 | RISK-BACKUP-01 | AST-DB-001 Customer database | Create the missing backup policy, fix the failing job, and enable immutable storage for tier 1 backups. | Head of Engineering | 2026-11-01 | medium | DET-BACKUP -> PASS |
| 17 | RISK-BACKUP-04 | AST-SRV-002 Reconciliation server | Create the missing backup policy, fix the failing job, and enable immutable storage for tier 1 backups. | IT Operations Manager | 2026-11-01 | medium | DET-BACKUP -> FAIL |
| 18 | RISK-BACKUP-05 | AST-STO-001 Customer documents storage | Create the missing backup policy, fix the failing job, and enable immutable storage for tier 1 backups. | Data Protection Officer | 2026-12-31 | medium | DET-BACKUP -> PASS |
