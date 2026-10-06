# SOC Detection Engineering

Practical detection engineering project built on a reusable SOC lab.

## Project status

**LAB-DET-001 — PowerShell Encoded Execution: functionally validated.**

The first use case demonstrates a reproducible detection-engineering cycle against Windows PowerShell telemetry collected by Sysmon and analyzed by Wazuh.

## Problem statement

Endpoint telemetry can be present without receiving the intended detection severity or classification.

LAB-DET-001 evaluated native Wazuh coverage for PowerShell encoded-command execution and identified a specific gap for the `-enc` alias.

## Validated result

Controlled testing demonstrated:

- normal PowerShell execution -> native rule `92027`, level 4;
- `-EncodedCommand <BASE64>` -> native rule `92057`, level 12;
- `-enc <BASE64>` before the custom rule -> native rule `92027`, level 4;
- inspection of native rule `92057` showed that its regex did not include the exact `enc` token;
- custom rule `100100` V1 detected `-enc <BASE64>`, but also generated a false positive for `-enc` with no argument;
- V2 required a Base64-looking argument and passed the final controlled positive and negative tests.

Final V2 behavior:

```text
-enc <valid-looking Base64> -> 100100 / level 12
-enc with no argument       -> no 100100; native 92027 / level 4
```

## Detection engineering workflow

```text
controlled activity
-> telemetry
-> native coverage assessment
-> reproducible gap
-> root-cause inspection
-> custom rule
-> false-positive discovery
-> tuning
-> positive/negative revalidation
-> documentation
```

## Repository structure

- `detection-rules/wazuh-rules.xml` — final Wazuh custom rule.
- `docs/use-case-design.md` — problem, hypothesis, data sources, and engineering decision.
- `docs/telemetry-analysis.md` — observed telemetry, root cause, and tuning analysis.
- `docs/coverage-matrix.md` — native and custom coverage matrix.
- `docs/validation-plan.md` — acceptance criteria and final controlled results.
- `docs/limitations.md` — scope and known limitations.
- `tests-or-validation/test-cases.md` — executed test cases.
- `samples/sanitized-events.json` — sanitized representative event evidence.
- `evidence/README.md` — public evidence manifest and publication policy.

## ATT&CK mapping

The validated detection is mapped to:

- `T1059.001 — Command and Scripting Interpreter: PowerShell`

The mapping is supported by the observed PowerShell process execution and the corresponding Wazuh detection context.

## Validation policy

A detection is not considered complete merely because it fires.

Each use case must demonstrate observable telemetry, repeatable positive testing, negative or benign testing, false-positive/noise analysis, tuning when required, evidence supporting the result, and justified ATT&CK mapping.

## Security and publication

Raw SOC evidence, secrets, credentials, tokens, personal information, internal addressing, and sensitive logs are not committed.

Only sanitized evidence suitable for public portfolio use is published.

## Current limitation

The final rule is validated only against the controlled LAB-DET-001 test set. It is not presented as universal PowerShell encoded-command coverage or as a production false-positive benchmark.
