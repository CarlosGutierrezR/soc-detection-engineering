# LAB-DET-001 — Validation Plan

## Objective

Validate that the custom rule detects the `-enc` encoded-command alias without classifying an empty `-enc` invocation as a valid encoded-command execution.

## Acceptance criteria

The use case is considered functionally validated when:

1. a controlled `-enc <BASE64>` execution produces Sysmon Event ID 1;
2. Wazuh assigns custom rule `100100` at level 12;
3. an `-enc` invocation without an argument does not trigger rule `100100`;
4. Wazuh Manager remains operational after loading the rule;
5. Wazuh configuration/ruleset validation returns exit code 0.

## Final V2 observations

| Check | Observed result | Status |
|---|---|---|
| Wazuh ruleset/config test | `wazuh-analysisd -t` -> exit code 0 | PASS |
| Manager after restart | `active` | PASS |
| Positive: `-enc <BASE64>` | rule `100100`, level 12 | PASS |
| Negative: `-enc` without payload | rule `92027`, level 4; no `100100` | PASS |

## Controlled-sample metrics

For the final V2 validation set directly executed after the tuning change:

- positive tests: 1;
- positive detections by rule `100100`: 1;
- negative tests targeting the V1 false positive: 1;
- negative tests incorrectly classified by rule `100100`: 0.

These counts demonstrate the intended behavior in the controlled test set only. They are not a production false-positive rate.

## Rollback

The custom rules directory was backed up before the change. Rollback consists of removing the custom LAB-DET-001 rule or restoring the pre-change custom-rules backup, followed by ruleset validation and a controlled manager restart.
