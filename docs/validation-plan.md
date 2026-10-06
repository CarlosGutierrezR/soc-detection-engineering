# LAB-DET-001 — Validation Plan

## Objective

Validate that V2 detects the observed `-enc <BASE64>` gap while avoiding an overbroad semantic claim when `-enc` has no payload.

## Acceptance criteria

V2 is functionally accepted when:

1. controlled `-enc <BASE64>` produces Sysmon Event ID 1;
2. Wazuh assigns custom rule `100100` at level 12;
3. empty `-enc` does not trigger rule `100100`;
4. Wazuh Manager remains operational after the rule change;
5. Wazuh configuration/ruleset validation returns exit code 0.

All five criteria were observed in the controlled final V2 acceptance run.

## Metrics boundary

The final acceptance pair contained one positive and one negative precision case. That is sufficient to prove the specific acceptance behavior, but it is **not** sufficient to estimate a production false-positive rate.

A longer normal-activity observation period remains pending.

## Reproducibility hardening

Still pending:

- capture `wazuh-logtest` output for representative native and custom cases;
- record exact `$PSVersionTable`;
- execute the V3 prefix research matrix before broadening the rule.

## CI

Repository CI validates XML well-formedness and the current PCRE2 contract using deterministic positive/negative strings. These tests support regression control but do not replace Wazuh's own rules engine.

## Rollback

The custom-rules directory was backed up before the change. Rollback consists of removing the LAB-DET-001 custom rule or restoring the pre-change backup, validating the ruleset, restarting Wazuh Manager in a controlled manner, and confirming service health.
