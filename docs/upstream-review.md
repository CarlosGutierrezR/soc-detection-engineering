# Upstream review status

## Wazuh issue / PR search

A targeted GitHub issue search was performed on 2026-10-06 using terms around:

- rule `92057` + PowerShell;
- `EncodedCommand` + Sysmon + PowerShell.

Those targeted searches returned no exact issue matches.

This does **not** prove that no related Wazuh issue or pull request exists. Broader issue/PR review is still required before opening an upstream report.

## Upstream contribution gate

Do not open an upstream issue or PR yet.

Before contacting Wazuh upstream:

1. capture exact Windows PowerShell version;
2. validate the broader accepted-prefix set;
3. capture reproducible `wazuh-logtest` results;
4. prepare sanitized event samples;
5. compare against the current upstream ruleset;
6. repeat a broader duplicate search.

An upstream contribution should describe a reproducible ruleset coverage issue, not only a local custom-rule workaround.
