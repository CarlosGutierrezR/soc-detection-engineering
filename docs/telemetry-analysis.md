# LAB-DET-001 — Telemetry Analysis

## Observed telemetry

### TC-00 — benign PowerShell baseline

A normal nested PowerShell execution produced:

- Sysmon Event ID 1 locally;
- PowerShell Event ID 4104 locally;
- Wazuh native rule `92027`, level 4.

This establishes that rule `92027` is generic PowerShell process-spawn coverage and is not evidence of encoded-command detection.

### TC-01 — `-EncodedCommand`

The controlled encoded command produced:

- Sysmon Event ID 1;
- PowerShell Event ID 4104 locally;
- command line containing `-EncodedCommand <BASE64>`;
- Wazuh native rule `92057`, level 12;
- ATT&CK mapping `T1059.001`.

### TC-02 — `-enc`

Using the same class of benign Base64 payload with the short alias produced:

- Sysmon Event ID 1;
- PowerShell Event ID 4104 locally;
- command line containing `-enc <BASE64>`;
- Wazuh native rule `92027`, level 4.

The telemetry was present; the gap was in classification/detection logic rather than collection.

## Root cause

The installed Wazuh rule `92057` used a PCRE2 expression whose encoded-command alternation included:

`encodedcommand|e|ea|ec|encodeda|encode|en|enco`

The exact token `enc` was absent.

Therefore, `-EncodedCommand` matched the native high-severity rule while `-enc` did not.

## Custom-rule tuning

### V1

The first custom rule matched `-enc` followed by whitespace or end-of-line.

It correctly detected valid `-enc <BASE64>` activity, but it also alerted on `-enc` with no argument. That execution failed in PowerShell, so this was treated as a false positive for the intended use case.

### V2

The command-line condition was tightened to require a Base64-looking argument:

`(?i)powershell\.exe.*\s-enc\s+[A-Za-z0-9+/]{8,}={0,2}(?:\s|$)`

Observed result:

- valid `-enc <BASE64>` -> custom rule `100100`, level 12;
- `-enc` without an argument -> native rule `92027`, level 4; custom rule `100100` did not fire.

## Interpretation

LAB-DET-001 demonstrates the complete engineering chain:

telemetry -> native coverage assessment -> reproducible gap -> root-cause inspection -> custom rule -> false-positive discovery -> tuning -> positive and negative revalidation.
