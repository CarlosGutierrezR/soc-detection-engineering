# LAB-DET-001 — Test Cases

All payloads are benign and limited to the authorized SOC lab.

The authoritative outcome matrix is maintained in [../docs/coverage-matrix.md](../docs/coverage-matrix.md). This file focuses on the test procedure rather than duplicating the same results table.

## Shared payload generation

```powershell
$script = 'Write-Output "SOC-DETECTION-TEST"'
$encoded = [Convert]::ToBase64String(
    [Text.Encoding]::Unicode.GetBytes($script)
)
```

## TC-00 — benign baseline

```powershell
powershell.exe -NoProfile -Command 'Write-Output "SOC-DETECTION-TEST-TC00"'
```

Purpose: establish the generic native PowerShell process-spawn behavior.

## TC-01 — native long-form positive

```powershell
powershell.exe -NoProfile -EncodedCommand $encoded
```

Purpose: verify native encoded-command coverage.

## TC-02 — native short-alias gap test

```powershell
powershell.exe -NoProfile -enc $encoded
```

Purpose: determine whether the short alias receives equivalent native classification.

## NEG-V1 / NEG-V2 — empty argument precision test

```powershell
powershell.exe -NoProfile -enc
```

Purpose: test whether the custom rule requires an argument that is consistent with its description.

An alert on this command can still be operationally suspicious. In LAB-DET-001 it is treated as a **precision mismatch relative to the rule semantics**, not proof that the activity is benign.

## V3 research

Broader PowerShell parameter-prefix testing is intentionally separated from the validated V2 result. See [../docs/v3-research-plan.md](../docs/v3-research-plan.md).
