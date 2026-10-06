# LAB-DET-001 — Environment

This table records the environment relevant to the observed LAB-DET-001 behavior. The root-cause finding is version-sensitive and should be revalidated after upgrades.

| Component | Observed version / state | Evidence status |
|---|---|---|
| Wazuh Manager | 4.14.7-1 | Verified in SOC baseline used by this project |
| Wazuh Agent on Windows endpoint | 4.14.7-1 | Verified in SOC baseline used by this project |
| Sysmon schema | 4.91 | Verified in SOC baseline used by this project |
| Windows endpoint | Windows 11 Pro 25H2 | Edition/release verified in SOC baseline; exact OS build was not re-captured in LAB-DET-001. Sysmon event showed powershell.exe file version 10.0.26100.9278 |
| Windows PowerShell | `powershell.exe` | Exact `$PSVersionTable.PSVersion` was not captured during LAB-DET-001 and remains a pending evidence item |
| Native Wazuh rule file | `/var/ossec/ruleset/rules/0800-sysmon_id_1.xml` | Directly inspected during LAB-DET-001 |
| Native rule | `92057` | Directly inspected |
| Rule start / command-line condition | rule starts at line 613; command-line PCRE2 observed at line 616 | Directly observed with `grep -n` in the lab |

## Native rule fragment observed

```xml
<rule id="92057" level="12">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.parentImage" type="pcre2">(?i)powershell\.exe</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)powershell\.exe.+\-\b(encodedcommand|e|ea|ec|encodeda|encode|en|enco)\b</field>
  ...
</rule>
```

## Version sensitivity

The finding must not be generalized to all Wazuh versions. A future Wazuh ruleset may change rule 92057 and remove, alter, or supersede this gap.

Likewise, the exact set of accepted Windows PowerShell parameter abbreviations is not inferred here. It must be tested on the endpoint version actually used by the lab.
