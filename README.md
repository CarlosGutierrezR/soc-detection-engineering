# SOC Detection Engineering

Practical detection engineering project built on a reusable SOC lab.

## Project status

**Current phase:** baseline audit and revalidation.

The repository contains historical work related to PowerShell encoded-command visibility in Wazuh. Those historical observations are preserved for traceability but are not considered current validated results until the tests are reproduced against the present SOC lab.

## Problem statement

Suspicious activity may be visible in endpoint or network telemetry without producing a reliable, actionable detection.

The project will follow this engineering cycle:

controlled activity -> telemetry -> detection hypothesis -> rule -> alert -> validation -> tuning -> false-positive analysis -> documentation

## Current evidence

- `docs/coverage-matrix.md` — historical PowerShell encoded-execution coverage notes; revalidation pending.

No custom detection rule is currently claimed as validated by this repository.

## Validation policy

A detection will not be considered complete merely because it fires.

Each use case must demonstrate:

- observable telemetry;
- repeatable positive testing;
- negative or benign testing;
- false-positive/noise analysis;
- tuning when required;
- evidence supporting the final result;
- justified ATT&CK mapping when applicable.

## Security and publication

Raw SOC evidence, secrets, credentials, tokens, personal information, and sensitive logs must not be committed.

Only sanitized evidence suitable for public portfolio use will be published.

## Next milestone

Revalidate the current SOC baseline and determine whether the historical PowerShell encoded-execution use case remains reproducible before designing or modifying detection logic.
