# LAB-DET-001 — V3 Research Plan

## Status

**Not implemented. Not validated in Wazuh.**

The current production-in-lab rule remains V2. V3 is a research candidate only.

## Why V3 is being considered

The validated LAB-DET-001 gap covers the exact `-enc` alias. Technical review identified a plausible broader question: Windows PowerShell may accept additional unambiguous prefixes of `EncodedCommand` that are not covered by native rule 92057 or the V2 custom rule.

Microsoft documents both `-EncodedArguments` and `-EncodedCommand` for Windows PowerShell 5.1, so a prefix such as `-encoded` may be ambiguous. The repository therefore does **not** assume that every prefix is valid.

## Candidate tokens to verify on the actual endpoint

Positive candidates to test only if Windows PowerShell accepts them:

```text
-enc
-encod
-encodedc
-encodedco
-encodedcom
-encodedcomm
-encodedcomma
-encodedcomman
```

Additional syntax variants to verify independently:

```text
/enc
quoted Base64 argument
case variations
Unicode dash variants
```

Ambiguity check:

```text
-encoded
```

This token must be tested specifically because both `EncodedArguments` and `EncodedCommand` exist.

## Candidate V3 pattern

The following pattern is **research-only** until endpoint and Wazuh tests pass:

```regex
(?i)powershell\.exe.*\s[-/](?:enc|encod|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman)\s+["']?[A-Za-z0-9+/]{8,}={0,2}
```

## Required validation sequence

1. Capture the exact Windows PowerShell version with `$PSVersionTable`.
2. Execute each candidate parameter with the same benign UTF-16LE/Base64 payload.
3. Record whether PowerShell accepts or rejects the parameter.
4. Capture Sysmon Event ID 1 for accepted cases.
5. Run the accepted-event samples through `wazuh-logtest`.
6. Run the same samples against the candidate V3 rule.
7. Add negative cases for `EncodedArguments`, `-encoding`, missing arguments, malformed Base64-looking values, and normal endpoint activity.
8. Only after all tests pass, decide whether V3 should replace V2.

## Promotion gate

V3 must not replace V2 until:

- accepted PowerShell prefixes are observed, not assumed;
- Wazuh behavior is reproduced for each accepted prefix;
- `wazuh-logtest` output is captured;
- negative cases pass;
- normal-activity observation does not reveal unacceptable noise.
