# 07 Assumptions and Limitations

## Required statements
1. Florence Inc. is fictional.
2. Evidence is simulated.
3. SentinelBridge evaluates supplied evidence.
4. The engine does not independently verify external infrastructure.
5. Framework mappings are illustrative and are not a certification or a compliance claim. Each control is mapped to one best-fit requirement per framework, so related requirements are deliberately left out. Check references against the current framework text before relying on them.
6. Risk calculations are scenario-based.
7. Detector thresholds are project assumptions (named constants at the top of each detector module).


## Design assumptions
- Break-glass accounts are privileged human accounts and are not exempt from MFA.
- `resource_scope` lists the permissions approved for an account's role.
- A firewall rule list with no administrative-port rule is a PASS.
- Accepting a risk does not turn a FAIL into a PASS. 

## Limitations
- **Evidence age:** the MVP measures time from `collected_at` and does not reject evidence for being old relative to the run time. Staleness is handled through control thresholds such as logging silence and backup age.
- **Broad exposure** means the literal any-address range only. Other very wide ranges are not flagged.
- **One invalid record rejects the whole input.** This is deliberate and strict.
- **Monte Carlo inputs** are illustrative and risks are independent.
- **Automated tests cover** validation, detection, findings, the risk calculator and Monte Carlo.
