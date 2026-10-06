# Upstream review status

## Targeted duplicate search

A targeted GitHub issue search was performed on 2026-10-06 using terms around:

- rule `92057` + PowerShell;
- `EncodedCommand` + Sysmon + PowerShell.

Those targeted searches returned no exact issue matches.

This does **not** prove that no related Wazuh issue or pull request exists. A broader duplicate review is still required before opening an upstream report.

## Native-ruleset consistency finding

Review of the official Wazuh v4.14.7 `0800-sysmon_id_1.xml` shows that three rules use closely related encoded-command token lists:

### Rule 92057

```regex
(?i)powershell\.exe.+\-\b(encodedcommand|e|ea|ec|encodeda|encode|en|enco)\b
```

This rule uses a trailing word boundary. In the controlled LAB-DET-001 case, `-enc` did not match and fell back to rule `92027`.

### Rule 92059

```regex
(?i)powershell\.exe.+\-(encodedcommand|e|ea|ec|encodeda|encode|en|enco)
```

Rule 92059 is context-specific: it depends on rule `92058` and describes an Application Compatibility Database launched from encoded PowerShell.

### Rule 92071

```regex
(?i)powershell\.exe.+\-(encodedcommand|e|ea|ec|encodeda|encode|en|enco)
```

Rule 92071 is also context-specific: it depends on rule `92070` and describes PowerShell created by WMI.

### Why this matters

Rules 92059 and 92071 omit the trailing `\b`. Because their alternation includes very short prefixes such as `e` and `en`, a command-line token beginning with `-enc...` can satisfy those regexes when the rules' additional context conditions are met.

This does not make 92059 or 92071 substitutes for 92057. It does show **inconsistent encoded-command token matching semantics inside the same native ruleset**, which is relevant evidence for a future upstream issue.

## Upstream contribution gate

Do not open an upstream issue or PR yet.

Before contacting Wazuh upstream:

1. capture the exact Windows PowerShell version;
2. validate which abbreviated parameter forms the actual endpoint accepts;
3. capture reproducible `wazuh-logtest` results;
4. prepare sanitized raw event samples;
5. compare the finding against the current upstream ruleset at submission time;
6. repeat a broader duplicate issue/PR search;
7. describe the 92057 vs 92059/92071 regex inconsistency without implying that the context-specific rules provide equivalent coverage.

An upstream contribution should describe a reproducible native-ruleset behavior with exact version, event sample, expected result, observed result, and minimal proposed change.
