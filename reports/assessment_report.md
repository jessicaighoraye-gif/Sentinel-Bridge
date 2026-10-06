# Assessment Report: Florence Inc.

Prepared from the SentinelBridge assessment results. Evidence is simulated. SentinelBridge evaluates the evidence it is given and does not verify external systems.

## 1. Scope and method
- Baseline assessment: `ASM-FLORENCE-INSECURE`, evidence collected 2026-10-02T09:00:00Z.
- Retest assessment: `ASM-FLORENCE-REMEDIATED`, evidence collected 2026-10-09T09:00:00Z.
- 12 detectors, one per control, run against every applicable asset (33 findings per run).
- Each finding is PASS, FAIL, INSUFFICIENT or INPUT_ERROR. Missing evidence is never treated as a failure.

## 2. Result summary
Baseline: **18 FAIL**, 15 PASS, 0 INSUFFICIENT, 0 INPUT_ERROR.
Failing findings by severity: critical 4, high 10, medium 4, low 0.


## 3. All findings (baseline and retest)
| Finding | Control | Asset | Baseline | Severity | Retest |
|---|---|---|---|---|---|
| FND-MFA-01 | CTRL-IAM-001 | AST-IDP-001 | FAIL | critical | PASS |
| FND-EXCESS-PRIV-01 | CTRL-IAM-002 | AST-IDP-001 | FAIL | medium | FAIL |
| FND-INACTIVE-ACCT-01 | CTRL-IAM-003 | AST-IDP-001 | FAIL | medium | PASS |
| FND-PASSWORD-01 | CTRL-IAM-004 | AST-IDP-001 | FAIL | medium | FAIL |
| FND-ENC-REST-01 | CTRL-DATA-001 | AST-DB-001 | FAIL | high | PASS |
| FND-ENC-REST-02 | CTRL-DATA-001 | AST-STO-001 | FAIL | high | PASS |
| FND-ENC-REST-03 | CTRL-DATA-001 | AST-STO-002 | PASS | none | PASS |
| FND-ENC-REST-04 | CTRL-DATA-001 | AST-BKP-001 | PASS | none | PASS |
| FND-ENC-TRANSIT-01 | CTRL-DATA-002 | AST-DB-001 | FAIL | high | PASS |
| FND-ENC-TRANSIT-02 | CTRL-DATA-002 | AST-APP-001 | PASS | none | PASS |
| FND-ENC-TRANSIT-03 | CTRL-DATA-002 | AST-SRV-001 | FAIL | high | FAIL |
| FND-ENC-TRANSIT-04 | CTRL-DATA-002 | AST-SRV-002 | PASS | none | PASS |
| FND-ENC-TRANSIT-05 | CTRL-DATA-002 | AST-STO-001 | PASS | none | PASS |
| FND-ENC-TRANSIT-06 | CTRL-DATA-002 | AST-STO-002 | PASS | none | PASS |
| FND-VULN-SW-01 | CTRL-END-001 | AST-APP-001 | PASS | none | PASS |
| FND-VULN-SW-02 | CTRL-END-001 | AST-SRV-001 | FAIL | high | FAIL |
| FND-VULN-SW-03 | CTRL-END-001 | AST-SRV-002 | FAIL | high | FAIL |
| FND-VULN-SW-04 | CTRL-END-001 | AST-END-001 | PASS | none | PASS |
| FND-VULN-SW-05 | CTRL-END-001 | AST-END-002 | PASS | none | PASS |
| FND-ENDPOINT-01 | CTRL-END-002 | AST-END-001 | PASS | none | PASS |
| FND-ENDPOINT-02 | CTRL-END-002 | AST-END-002 | FAIL | high | FAIL |
| FND-LOGGING-01 | CTRL-LOG-001 | AST-LOG-001 | FAIL | medium | FAIL |
| FND-CLOUD-EXPOSURE-01 | CTRL-CLD-001 | AST-STO-001 | FAIL | critical | PASS |
| FND-CLOUD-EXPOSURE-02 | CTRL-CLD-001 | AST-STO-002 | FAIL | critical | PASS |
| FND-CLOUD-EXPOSURE-03 | CTRL-CLD-001 | AST-STO-003 | PASS | none | PASS |
| FND-BACKUP-01 | CTRL-BCP-001 | AST-DB-001 | FAIL | high | PASS |
| FND-BACKUP-02 | CTRL-BCP-001 | AST-APP-001 | PASS | none | PASS |
| FND-BACKUP-03 | CTRL-BCP-001 | AST-SRV-001 | PASS | none | PASS |
| FND-BACKUP-04 | CTRL-BCP-001 | AST-SRV-002 | FAIL | high | FAIL |
| FND-BACKUP-05 | CTRL-BCP-001 | AST-STO-001 | FAIL | high | PASS |
| FND-BACKUP-06 | CTRL-BCP-001 | AST-STO-002 | PASS | none | PASS |
| FND-BACKUP-07 | CTRL-BCP-001 | AST-STO-003 | PASS | none | PASS |
| FND-REMOTE-ACCESS-01 | CTRL-NET-001 | AST-NET-001 | FAIL | critical | PASS |


## 4. Evidence gaps
None in the baseline run. Every applicable asset had enough evidence for a decision.

## 5. Risk and uncertainty
Risks are in `risk/risk_register.csv` (likelihood x impact, method in `docs/06_risk_methodology.md`).
Monte Carlo on the 6 highest risks (illustrative assumptions, 10,000 trials): expected annual loss $1,005,604 before and $196,978 after remediation; P90 $2,615,105 before and $564,716 after.

## 6. Traceability
Every failing finding links to its detector, evidence records, control, framework mapping, risk, remediation and test in `traceability_matrix.csv`.

## 7. Limits
Framework mappings are illustrative and do not imply certification. Loss figures are scenario assumptions. See `docs/07_assumptions_and_limitations.md`.
