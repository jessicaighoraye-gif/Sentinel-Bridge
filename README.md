# SentinelBridge

**Security assurance, risk and business decision engine.** 

SentinelBridge turns structured security evidence into a defensible business decision, and keeps every step traceable.

```
Evidence > Validation > Detection > Finding > Control mapping > Risk > Remediation > Re-test > Business decision
```

## The problem
Security teams hold evidence from many systems but need one consistent way to say: is the condition really present, is the evidence enough to say so, what risk does it create, what should be fixed, did the fix work, and what should management decide. 

## Florence Inc.
A fictional regional fintech and payments company: 100 employees (30 remote), customer personal data and payment data, 13 modeled assets. All evidence is simulated.

## The solution
- Validates evidence against JSON schemas before any detection.
- Runs **12 detectors**, one per control. Each finding is **PASS, FAIL, INSUFFICIENT or INPUT_ERROR**. 
- Generates timestamped findings, then maps each control to one best-fit requirement in **NIST CSF 2.0** and **ISO/IEC 27001:2022 Annex A**.
- Builds a risk register (likelihood x impact) and a **Monte Carlo** estimate of annual loss for the top risks.
- Produces remediation, then **re-runs the same detector** to prove FAIL becomes PASS.


Phase 1 (evidence to findings) proves the engine works. Phase 2 (risk to decision) shows what an organization does with the output.

## Detection controls
| Control | Name | Detector | Severity on FAIL |
|---|---|---|---|
| CTRL-IAM-001 | Privileged Accounts Without MFA | DET-MFA | critical |
| CTRL-IAM-002 | Excessive User Privileges | DET-EXCESS-PRIV | medium |
| CTRL-IAM-003 | Inactive Enabled Accounts | DET-INACTIVE-ACCT | medium |
| CTRL-IAM-004 | Password Policy Violations | DET-PASSWORD | medium |
| CTRL-DATA-001 | Sensitive Data Unencrypted at Rest | DET-ENC-REST | high |
| CTRL-DATA-002 | Sensitive Data Unencrypted in Transit | DET-ENC-TRANSIT | high |
| CTRL-END-001 | Unsupported or Vulnerable Software | DET-VULN-SW | high |
| CTRL-END-002 | Missing Endpoint Protection | DET-ENDPOINT | high |
| CTRL-LOG-001 | Inadequate Security Logging and Monitoring | DET-LOGGING | medium |
| CTRL-CLD-001 | Exposed Cloud Storage Containing Sensitive Data | DET-CLOUD-EXPOSURE | critical |
| CTRL-BCP-001 | Inadequate Backup and Recovery Controls | DET-BACKUP | high |
| CTRL-NET-001 | Unrestricted Remote Access | DET-REMOTE-ACCESS | critical |

## Example input
One account record from the `insecure_state` sample in `inputs/evidence_samples.json`:
```json
{"record_id": "ACC-0003", "asset_id": "AST-IDP-001", "user_id": "u003", "account_type": "human", "account_status": "enabled", "privileged_status": true, "administrative_status": true, "mfa_enrollment_status": "enrolled", "mfa_enforcement_status": "not_enforced", "assigned_permissions": ["iam:manage", "infra:deploy"], "used_permissions": ["iam:manage", "infra:deploy"], "resource_scope": [], "usage_period": 90, "last_login": "2026-09-22T09:00:00Z", "account_creation_date": "2024-07-21", "password_last_set": "2026-09-24"}
```

## Example output
`reports/findings.json` entry for that evidence:
```json
{
  "finding_id": "FND-MFA-01",
  "assessment_id": "ASM-FLORENCE-INSECURE",
  "detector_id": "DET-MFA",
  "control_id": "CTRL-IAM-001",
  "asset_id": "AST-IDP-001",
  "status": "FAIL",
  "severity": "critical",
  "detected_at": "2026-10-02T23:40:06Z",
  "evidence_status": "sufficient",
  "evidence_ref": [
    "identity:ACC-0003",
    "identity:ACC-0007",
    "identity:ACC-0011"
  ],
  "description": "3 of 12 in-scope privileged accounts fail: u003 MFA not enforced; u007 MFA not enrolled; u011 MFA not enrolled."
}
```
The demo then shows `RISK-MFA-01` (likelihood 4 x impact 5 = 20, Critical), remediation `REM-MFA-01`, and the retest result `FAIL -> PASS`.

## The demo story (`insecure_state` then `remediated_state`)
- 33 findings: 18 FAIL, 15 PASS.
- 3 of 12 privileged accounts without MFA, 8 stale accounts, unencrypted customer database, 2 unsupported payment servers, public buckets holding sensitive data, RDP open to 0.0.0.0/0.
- After one week of fixes: 10 of 18 risks closed, including every critical one. 8 remain and need management decisions.

## How to run (Windows, Powershell terminal)
Python 3.10 or newer. From the project folder (the install step is required, numpy is used by the loss simulation):
```
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python -m pytest
python examples\end_to_end_demo.py
python -m engine.evaluator inputs\evidence_samples.json --sample insecure_state
```
In PowerShell use `.venv\Scripts\Activate.ps1`. On macOS or Linux use `source .venv/bin/activate` and forward slashes.

## Build steps
How SentinelBridge was built, in order. Each stage was tested before the next one started.

| Step | What was built | Where | Check it with |
|---|---|---|---|
| 1 | Florence Inc.: profile, 13 assets, data tiers | `company/` | read the files |
| 2 | The 12 controls and their NIST CSF 2.0 and ISO 27001 mapping | `controls/` | read the files |
| 3 | Detection rules: PASS, FAIL, INSUFFICIENT, INPUT_ERROR for each control | `docs/05_detection_methodology.md` | read the file |
| 4 | Data formats: input, evidence, finding | `inputs/schema/` | `python -m pytest tests/test_input_validation.py tests/test_finding_format.py` |
| 5 | Hypothetical evidence: 30 samples in one file | `inputs/evidence_samples.json` | `python -m pytest tests/test_samples.py` |
| 6 | Engine: validators, 12 detectors, findings, pipeline | `engine/` | `python -m pytest tests/test_detectors.py tests/test_detector_edge_cases.py tests/test_finding_generator.py tests/test_pipeline.py` |
| 7 | Risk: formulas, finished risk register, Monte Carlo loss analysis | `risk/` | `python -m pytest tests/test_risk_calculator.py  tests/test_monte_carlo.py` |
| 8 | Remediation, retest and the business decision memo | `remediation/`, `decisions/`, `traceability_matrix.csv` | `python examples/end_to_end_demo.py` |
| 9 | Documentation | `docs/`, this README | read the files |

Steps 1 to 3 and the documents in step 8 are written files. Steps 4 to 7 are code with tests. The demo ties the stages together.


- **Name and version:** SentinelBridge 0.1.0 (a security assurance, risk and business decision engine for the fictional Florence Inc.).
- **Python:** 3.10 or newer.
- **Libraries** (all in `requirements.txt`): `jsonschema` 4.18 or newer (checks inputs against the schemas), `pyyaml` 6.0 or newer (reads the company and control files), `numpy` 1.26 or newer (the Monte Carlo loss simulation), `pytest` 7.0 or newer (the tests).
- **Tests:** they live in `tests/`. Run `python -m pytest` from the project folder, so that the `engine`, `risk` and `controls` folders can be imported.

## Testing
`python -m pytest` runs 234 tests:
- **Gate 1:** schema and validator tests, including every INPUT_ERROR case.
- **Gate 2:** all 12 detectors for PASS, FAIL (with re-test), INSUFFICIENT and INPUT_ERROR, edge cases, the finding generator, and the Input > Validation > Detection > Finding pipeline.
- **Samples:** all 30 evidence samples are run through the engine and compared with the result each one states.
- **Risk:** the formulas, every row of the finished risk register (recomputed from the engine's findings), and Monte Carlo accuracy (seeded, and close to the exact formula).



## Risk methodology
Inherent risk = likelihood x impact (1 to 25). Residual = inherent x (1 - control effectiveness). Impact comes from asset criticality. Monte Carlo (Poisson events, lognormal loss, seeded) is an uncertainty layer, not the primary model. See `docs/06_risk_methodology.md`. Loss figures are illustrative assumptions.

## Traceability
`traceability_matrix.csv` (in the project root) links each failing finding: security issue, detector, input evidence, finding, control and framework mapping, risk, remediation, test, and retest result.

## Limitations
Fictional company, simulated evidence, no live integrations. The engine evaluates supplied evidence and does not verify external systems. Framework mappings are illustrative, not a certification. See `docs/07_assumptions_and_limitations.md`.

## Where to look
| Folder | Contents |
|---|---|
| `company/`, `controls/` | Florence model, 12 controls, framework map |
| `inputs/` | Schemas and one evidence file with 30 samples |
| `engine/` | Validators, 12 detectors, findings pipeline |
| `risk/`, `remediation/`, `decisions/` | Phase 2 logic and outputs |
| `reports/` | Engine output (findings, Monte Carlo) and the assessment report |
| `traceability_matrix.csv` | Evidence to decision, one row per failing finding |
| `docs/` | Charter, scope, architecture, methodologies |
| `tests/` | 234 tests, one flat folder (see `tests/README.md`) |
