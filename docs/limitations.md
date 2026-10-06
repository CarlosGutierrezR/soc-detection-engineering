# LAB-DET-001 — Limitations

The final rule is deliberately narrow. Its current validation supports only the behavior demonstrated in the controlled SOC lab.

Known limitations:

- The rule is validated for Windows PowerShell process creation represented by Sysmon Event ID 1.
- It requires the parent image to end in `powershell.exe`.
- It targets the exact short alias `-enc`; other aliases remain dependent on native coverage or future engineering work.
- The Base64 expression is heuristic. It checks the character set, minimum length, and optional padding, but does not prove that the argument decodes successfully or represents UTF-16LE PowerShell content.
- The rule does not attempt to detect encoded content passed through other shells, interpreters, process-launch chains, script hosts, or alternative PowerShell implementations.
- Only a small controlled test set was used. No production-scale false-positive rate is claimed.
- Event-to-alert latency was not included as a project metric because a repeatable measurement set was not collected.
- PowerShell Event ID 4104 was confirmed locally for the controlled tests, but the use case's final Wazuh detection logic is based on Sysmon Event ID 1.
- Future Wazuh ruleset updates may add native coverage for `-enc`; the custom rule must be reviewed after upgrades to avoid redundant detections.

The current result should therefore be described as a validated lab detection for a specific observable gap, not universal PowerShell encoded-command coverage.
