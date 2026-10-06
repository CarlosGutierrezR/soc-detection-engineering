# Evidence — LAB-DET-001

This directory documents the evidence chain for the use case.

## Publication model

Primary evidence was captured from the real controlled executions and the Wazuh interface during LAB-DET-001.

The original screenshots contain operational lab metadata such as private addressing, host/user identifiers, GUIDs, hashes, process IDs, timestamps, and internal names. Those raw screenshots are retained outside the public repository.

For public portfolio review, this repository publishes **sanitized visual evidence summaries** derived from the primary screenshots:

- [Native gap evidence](lab-det-001/native-gap-evidence.svg)
- [Custom-rule final validation](lab-det-001/final-validation-evidence.svg)

The full technical chain is documented in [LAB-DET-001 case study](../docs/LAB-DET-001-case-study.md).

## Evidence manifest

| ID | Primary observation | Portfolio evidence |
|---|---|---|
| E1 | TC-01 Wazuh command line contained `-EncodedCommand <BASE64>` | native gap visual + case study |
| E2 | TC-01 classified as `92057 / level 12`, T1059.001 | native gap visual |
| E3 | TC-02 Wazuh command line contained `-enc <BASE64>` | native gap visual + case study |
| E4 | TC-02 classified as `92027 / level 4` | native gap visual |
| E5 | V1 produced `100100 / level 12` for valid activity and also for empty `-enc` | final validation visual + case study |
| E6 | V2 positive used `-enc <BASE64>` | final validation visual |
| E7 | V2 positive classified as `100100 / level 12`, T1059.001 | final validation visual |
| E8 | V2 negative used `-enc` with no argument | final validation visual |
| E9 | V2 negative classified as native `92027 / level 4`, with no `100100` | final validation visual |

## Integrity rule

No portfolio screenshot or summary should be treated as evidence of an observation that was not actually produced during the controlled lab run. The written case study and test matrix contain only observed results from LAB-DET-001.
