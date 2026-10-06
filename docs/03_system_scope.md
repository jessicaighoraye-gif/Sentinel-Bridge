# 03 System Scope

## In scope
- **Company model:** `company/` (profile, 13 assets, 4 data classification tiers).
- **Controls:** 12, each with one detector (`controls/security_controls.yaml`).
- **Evidence:** 8 simulated evidence blocks inside each sample.
- **Samples:** one file, `inputs/evidence_samples.json`, with 30 hypothetical samples. It includes the 5 original scenarios (`secure_state`, `insecure_state`, `insufficient_evidence`, `invalid_input`, `remediated_state`).
- **Engine:** validators, 12 detectors, finding generator, evaluator.
- **Decision layer:** control mapping, risk register, Monte Carlo, remediation, retest, business decision, traceability.

## Controls
| Control | Name |
|---|---|
| CTRL-IAM-001 | Privileged Accounts Without MFA |
| CTRL-IAM-002 | Excessive User Privileges |
| CTRL-IAM-003 | Inactive Enabled Accounts |
| CTRL-IAM-004 | Password Policy Violations |
| CTRL-DATA-001 | Sensitive Data Unencrypted at Rest |
| CTRL-DATA-002 | Sensitive Data Unencrypted in Transit |
| CTRL-END-001 | Unsupported or Vulnerable Software |
| CTRL-END-002 | Missing Endpoint Protection |
| CTRL-LOG-001 | Inadequate Security Logging and Monitoring |
| CTRL-CLD-001 | Exposed Cloud Storage Containing Sensitive Data |
| CTRL-BCP-001 | Inadequate Backup and Recovery Controls |
| CTRL-NET-001 | Unrestricted Remote Access |

## Out of scope
Real AWS, Azure, Entra ID, Okta or Splunk integrations. A SIEM. Vulnerability scanning. Endpoint agents. Machine learning. Predictive anomaly detection. Full OCSF. Production deployment. Automated remediation of real infrastructure.

