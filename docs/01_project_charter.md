# 01 Project Charter

**Project:** SentinelBridge, a security assurance, risk and business decision engine.
**Organization modeled:** Florence Inc., a fictional regional fintech and payments company (100 employees, 30 remote).
**Context:** UBI Stage 9B final project.

## Purpose
Show how security evidence becomes a defensible business decision through a traceable, testable workflow:

Evidence, validation, detection, finding, control mapping, risk, remediation, re-test, decision.

## Why Florence Inc. exists
Real organizations cannot share their evidence, findings or risk positions. Florence is a deliberately small fictional payments company, so the full chain can be shown openly with realistic data types (customer personal data, payment data, remote staff) and without exposing anything confidential.

## Objectives
1. Accept structured security evidence and validate it against schemas.
2. Run 12 detectors and produce PASS, FAIL, INSUFFICIENT or INPUT_ERROR with timestamped findings.
3. Map each control to its best-fit requirement in NIST CSF 2.0 and ISO/IEC 27001:2022 Annex A.
4. Assess risk (likelihood x impact) and quantify uncertainty with Monte Carlo.
5. Produce remediation, verify it by re-running the same detector, and generate a business decision.
6. Keep every result traceable by ID, with automated tests for the engine and the risk maths.

## Two phases
- **Phase 1, assurance engine:** evidence to findings. Proves the engine works.
- **Phase 2, decision layer:** findings to risk, remediation, retest and decision.

## Success criteria
- One complete chain works end to end: FAIL, risk, remediation, retest, PASS (see `examples/end_to_end_demo.py`).
- 231 automated tests pass.
- A non-technical reader can follow `decisions/business_decision.pdf`.

## Out of scope
Production integrations, a SIEM, vulnerability scanning, machine learning, a web application. See `03_system_scope.md`.
