# LAB-DET-001 — PowerShell Encoded Execution

## Problem

Endpoint telemetry can contain a PowerShell encoded-command execution while the native Wazuh ruleset classifies the event only as generic PowerShell activity.

The use case evaluates whether the short `-enc` parameter alias receives the same detection treatment as `-EncodedCommand`.

## Detection hypothesis

If Windows PowerShell spawns another PowerShell process using `-enc` with a Base64-looking argument, Sysmon Event ID 1 should contain the relevant command line and Wazuh should raise a high-severity encoded-command alert.

## Data sources

- Sysmon Event ID 1 — Process Creation.
- Microsoft-Windows-PowerShell/Operational Event ID 4104 — Script Block Logging.
- Wazuh Windows event-channel ingestion.

## Native baseline

Controlled tests demonstrated:

- normal PowerShell execution -> native rule `92027`, level 4;
- `-EncodedCommand <BASE64>` -> native rule `92057`, level 12;
- `-enc <BASE64>` -> native rule `92027`, level 4.

Inspection of the installed native rule `92057` showed that its PCRE2 alternation covered several PowerShell encoded-command abbreviations but did not include the exact `enc` token.

## Engineering decision

A custom rule was added rather than modifying the native Wazuh ruleset.

The final rule:

- requires Sysmon Event ID 1 through `sysmon_event1`;
- requires the parent image to end in `powershell.exe`;
- requires `-enc` followed by a Base64-looking argument of at least eight characters;
- maps to MITRE ATT&CK `T1059.001 — PowerShell`.

## Outcome

The final V2 rule detects the controlled `-enc <BASE64>` execution at level 12 while no longer matching an `-enc` invocation with no argument.

See:

- `../detection-rules/wazuh-rules.xml`
- `validation-plan.md`
- `../tests-or-validation/test-cases.md`
- `limitations.md`
