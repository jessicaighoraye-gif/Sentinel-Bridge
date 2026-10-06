# What the tests do

Run them all with `python -m pytest`. Nothing here connects to the internet or changes any project file.

All test evidence comes from ONE file: `inputs/evidence_samples.json` (30 hypothetical samples). The first 5 are written out in full. The other 25 store only their changes to another sample, and `engine/samples.py` rebuilds them.
The rules that evidence must follow are the three schema files in `inputs/schema/`. Tests do not have their own schemas.

| File | What it proves |
|---|---|
| `conftest.py` | Hands each test a fresh copy of one named sample |
| `helpers.py` | Small helpers: run one detector on its own; count how often a detector was called |
| `test_input_validation.py` | Good input is accepted and malformed input is rejected as INPUT_ERROR |
| `test_finding_format.py` | A finding record follows the finding schema |
| `test_timestamp.py` | Time helpers, and that the engine's own clock sets `detected_at` |
| `test_detectors.py` | Each of the 12 detectors gives PASS, FAIL (and passes after the fix), INSUFFICIENT and INPUT_ERROR as designed. The expected results are at the top of the file |
| `test_detector_edge_cases.py` | Tricky single cases, for example "accepted risk is still a FAIL" |
| `test_finding_generator.py` | Findings get their ID and timestamp from the engine |
| `test_pipeline.py` | The whole chain: input, validation, detection, finding, command line |
| `test_samples.py` | All 30 samples produce the result each one states, and variations are rebuilt correctly from their changes |
| `test_risk_calculator.py` | Risk formulas and rating bands |
| `test_risk_register.py` | Every row of the finished risk register matches the engine and the formulas
| `test_monte_carlo.py` | The loss simulation is repeatable and agrees with the exact formula |
