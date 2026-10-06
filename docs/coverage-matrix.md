# Coverage Matrix — LAB-DET-001 PowerShell Encoded Execution

## Objective

Evaluate native Wazuh coverage for PowerShell encoded-command execution, reproduce any classification gap, and validate a tuned custom rule where required.

## Telemetry

- Sysmon Event ID 1 — Process Creation.
- Microsoft-Windows-PowerShell/Operational Event ID 4104 — Script Block Logging.
- Wazuh Windows event-channel ingestion.

## Coverage matrix

| Test | Behavior | Sysmon EID 1 | PowerShell 4104 local | Wazuh result | Interpretation |
|---|---|---:|---:|---|---|
| TC-00 | PowerShell without encoded argument | Yes | Yes | `92027` / level 4 | Generic PowerShell baseline |
| TC-01 | `-EncodedCommand <BASE64>` | Yes | Yes | `92057` / level 12 | Native encoded-command detection |
| TC-02 | `-enc <BASE64>` before custom rule | Yes | Yes | `92027` / level 4 | Native classification gap reproduced |
| TC-02-R1 | `-enc <BASE64>` with custom V1 | Yes | Not required for rule decision | `100100` / level 12 | Positive detection |
| NEG-V1 | `-enc` with no argument | Yes | Not required for rule decision | `100100` / level 12 | False positive discovered |
| TC-02-V2 | `-enc <BASE64>` with tuned V2 | Yes | Not required for rule decision | `100100` / level 12 | Final positive PASS |
| NEG-V2 | `-enc` with no argument | Yes | Not required for rule decision | `92027` / level 4 | Final negative PASS; no `100100` |

## Root cause

The installed native Wazuh rule `92057` matched several abbreviations of `EncodedCommand`, but its observed PCRE2 alternation did not include the exact `enc` token.

This explains why the long form received the encoded-command rule while `-enc` fell back to generic PowerShell process-spawn detection.

## Final custom rule

The tuned rule requires:

```text
Sysmon Event ID 1
AND parentImage ends with powershell.exe
AND commandLine contains -enc followed by a Base64-looking argument
```

Final Wazuh rule ID: `100100`  
Final level: `12`  
ATT&CK: `T1059.001 — PowerShell`

## Controlled validation outcome

Final V2 controlled set:

- positives executed: 1;
- positives detected by `100100`: 1;
- negatives executed: 1;
- negatives incorrectly detected by `100100`: 0.

These numbers describe only the final controlled V2 validation set and must not be interpreted as a production false-positive rate.
