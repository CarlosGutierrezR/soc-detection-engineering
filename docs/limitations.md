# LAB-DET-001 — Limitations

The final V2 rule is deliberately narrow. Its validation supports only behavior demonstrated in the controlled SOC lab.

- The rule is validated for Windows PowerShell process creation represented by Sysmon Event ID 1.
- The parent-process requirement ends in `powershell.exe` because the rule intentionally preserves parity with native Wazuh rule `92057`. This excludes launches from other parents and must not be interpreted as evidence that those chains are benign.
- V2 targets the exact short alias `-enc`. Technical review identified plausible additional prefixes; those are tracked in `v3-research-plan.md` and remain unvalidated.
- Microsoft documents both `EncodedArguments` and `EncodedCommand` for Windows PowerShell 5.1. The repository therefore does not assume which longer prefixes are accepted; the actual endpoint must decide through observation.
- The Base64 expression is heuristic. It checks character shape, minimum length, and optional padding but does not prove successful decoding or UTF-16LE PowerShell semantics.
- Quoted Base64 arguments, slash-prefixed parameters, Unicode dash variants, and case/prefix variants outside current V2 coverage require separate validation.
- Only a small controlled test set was used. No production-scale false-positive rate is claimed.
- No sustained normal-activity observation period has yet been measured for this rule.
- Event-to-alert latency was not measured with a repeatable sample set.
- PowerShell Event ID 4104 was confirmed locally for the controlled tests; LAB-DET-001 does not claim ingestion of those exact 4104 events into Wazuh.
- Reproducible `wazuh-logtest` captures are still pending evidence hardening.
- Future Wazuh ruleset updates may add native coverage and make the custom rule redundant.
- The exact Windows PowerShell version from `$PSVersionTable` was not captured during the original run and remains a pending environment-evidence item.

The current result is therefore a validated lab detection for a specific observed Wazuh 4.14.7 ruleset gap, not universal PowerShell encoded-command coverage.
