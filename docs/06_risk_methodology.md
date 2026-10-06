# 06 Risk Methodology

The conventional model comes first. Monte Carlo is an advanced layer on top.

## 1. Primary model
```
Inherent risk = Likelihood x Impact          (1 to 25)
Residual risk = Inherent risk x (1 - Control effectiveness)
```
- **Likelihood** (1 Rare, 2 Unlikely, 3 Possible, 4 Likely, 5 Almost certain) is set per control in `risk/risk_parameters.yaml`, with the threat it represents.
- **Impact** comes from the criticality of the affected asset in `company/asset_inventory.yaml`: low 2, medium 3, high 4, critical 5.
- **Rating bands:** Low 1 to 4, Medium 5 to 9, High 10 to 16, Critical 17 to 25.
- **Control effectiveness** is 0 while the detector fails. When the retest passes, it becomes the control's `effectiveness_when_passing`.

One risk is created for each FAIL finding. INSUFFICIENT findings are evidence gaps, not risks.

## 2. Treatment
Rules in `decisions/decision_matrix.yaml` pick the treatment, target date and approver from the rating band and the remediation effort. Critical and High: Mitigate (7 and 30 days). Medium: Mitigate, or Accept when effort is high. Low: Accept. Acceptance is time-boxed and needs a compensating control and sign-off.

## 3. Monte Carlo
Purpose: show the uncertainty around the highest risks, and the value of remediation.

- **Selection:** top 6 risks by inherent score, ties broken by expected loss.
- **Model per risk:** events per year ~ Poisson(annual event rate). Loss per event ~ Lognormal(median, sigma). Risks are independent.
- **After retest:** the event rate is multiplied by (1 - effectiveness) for risks whose detector passed.
- **Outputs:** expected loss, median, P90, probability of exceeding a loss threshold of $250,000 a year, and a loss distribution.
- **Reproducible:** 10,000 trials, seed 42.
- **Check:** the analytic mean is rate x median x exp(sigma^2 / 2). Tests confirm the simulation agrees with it.

## 4. Assumptions
These are illustrative project assumptions for a fictional company. They are not measurements and not industry statistics.

| Control | Threat | L | Eff. when passing | Events/yr | Median loss | Sigma |
|---|---|---|---|---|---|---|
| CTRL-IAM-001 | Attacker takes over a privileged account protected only by a password | 4 | 90% | 0.25 | $250,000 | 1.0 |
| CTRL-IAM-002 | A compromised account uses permissions it should never have held | 3 | 70% | 0.1 | $100,000 | 1.0 |
| CTRL-IAM-003 | Attacker reuses a dormant account that nobody monitors | 3 | 80% | 0.1 | $80,000 | 1.0 |
| CTRL-IAM-004 | Weak password policy lets attackers guess or stuff credentials | 3 | 60% | 0.1 | $90,000 | 1.0 |
| CTRL-DATA-001 | Unencrypted customer data is read after theft of storage or a snapshot | 3 | 90% | 0.06 | $600,000 | 1.1 |
| CTRL-DATA-002 | Sensitive traffic is intercepted or downgraded in transit | 3 | 85% | 0.06 | $200,000 | 1.0 |
| CTRL-END-001 | Attacker exploits software the vendor no longer patches | 3 | 80% | 0.15 | $300,000 | 1.1 |
| CTRL-END-002 | Malware runs on a device with no working protection | 4 | 80% | 0.2 | $150,000 | 1.0 |
| CTRL-LOG-001 | An intrusion goes unnoticed because required logs are missing | 3 | 70% | 0.12 | $120,000 | 1.0 |
| CTRL-CLD-001 | Sensitive data in a public bucket is found and downloaded | 5 | 95% | 0.3 | $400,000 | 1.1 |
| CTRL-BCP-001 | Ransomware or failure destroys data with no usable backup | 2 | 85% | 0.04 | $500,000 | 1.0 |
| CTRL-NET-001 | Attacker reaches an administrative port exposed to the internet | 5 | 90% | 0.4 | $450,000 | 1.1 |

## 5. Limits
- Likelihood and loss inputs are scenario judgments. Change them in the YAML and rerun.
- Risks are treated as independent, which understates correlated events.
- Impact uses asset criticality only. It does not model data volume or regulatory penalties.
