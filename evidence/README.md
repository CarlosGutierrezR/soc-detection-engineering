# Evidence — LAB-DET-001

## Evidence hierarchy

1. **Primary lab observations:** real controlled executions, Wazuh Document Details, and the real `alerts.json` record captured during TC-02.
2. **Sanitized technical evidence:** redacted JSON retaining the actual event/rule structure.
3. **Presentation summaries:** SVGs derived from the primary observations for quick recruiter review.

The SVGs are **not** treated as substitutes for primary technical evidence.

## Published evidence

- [Sanitized real TC-02 Wazuh alert JSON](lab-det-001/tc02-native-alert-sanitized.json)
- [Native gap presentation summary](lab-det-001/native-gap-evidence.svg)
- [Custom-rule validation presentation summary](lab-det-001/final-validation-evidence.svg)
- [Complete technical case study](../docs/LAB-DET-001-case-study.md)

## Primary observations represented

| ID | Observation |
|---|---|
| E1 | TC-01 command line contained `-EncodedCommand <BASE64>` |
| E2 | TC-01 classification was `92057 / level 12`, T1059.001 |
| E3 | TC-02 command line contained `-enc <BASE64>` |
| E4 | TC-02 classification was `92027 / level 4` |
| E5 | V1 matched both valid `-enc <BASE64>` and an empty `-enc` invocation |
| E6 | V2 positive used `-enc <BASE64>` |
| E7 | V2 positive classified as `100100 / level 12`, T1059.001 |
| E8 | V2 negative ended at `-enc` with no payload |
| E9 | V2 negative classified as native `92027 / level 4`; custom `100100` absent |

## Pending reproducible evidence

`wazuh-logtest` outputs were **not captured during the original run** and are not fabricated here.

The next evidence-hardening step is to replay sanitized representative events through the actual Wazuh 4.14.7 logtest engine and commit the resulting outputs.

## Publication policy

Raw screenshots are retained outside the public repository because they contain unnecessary operational metadata such as internal addressing, usernames, GUIDs, hashes, process IDs, and timestamps.

No published artifact should be treated as evidence for an observation that was not actually produced in the controlled lab.
