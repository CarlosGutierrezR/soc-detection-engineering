# Evidence — LAB-DET-001

## Evidence hierarchy

1. **Primary lab observations:** real controlled executions, Wazuh Document Details, the real `alerts.json` record captured during TC-02, and the real alert document exported for TC-02-V2.
2. **Sanitized technical evidence:** redacted JSON retaining the actual event/rule structure, plus redacted Wazuh screenshots.
3. **Presentation summaries:** SVGs derived from the primary observations for quick recruiter review.

The SVGs are **not** treated as substitutes for primary technical evidence.

## Published evidence

- [Sanitized real TC-02 Wazuh alert JSON](lab-det-001/tc02-native-alert-sanitized.json) — native gap (E3/E4)
- [Sanitized real TC-02-V2 Wazuh alert JSON](lab-det-001/tc02-v2-custom-alert-sanitized.json) — custom rule `100100` positive (E6/E7)
- [Redacted screenshot: TC-02-V2 command line and parent image](lab-det-001/screenshots/e6-v2-positive-commandline.png) — E6
- [Redacted screenshot: TC-02-V2 rule fields](lab-det-001/screenshots/e7-v2-positive-rule-fields.png) — E7
- [Redacted screenshot: alert list with `100100` / level 12](lab-det-001/screenshots/e7-v2-positive-alert-list.png) — E7
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
| E6 | V2 positive used `-enc <BASE64>` (published: TC-02-V2 JSON + screenshot) |
| E7 | V2 positive classified as `100100 / level 12`, T1059.001 (published: TC-02-V2 JSON + 2 screenshots) |
| E8 | V2 negative ended at `-enc` with no payload |
| E9 | V2 negative classified as native `92027 / level 4`; custom `100100` absent |

## Pending reproducible evidence

`wazuh-logtest` outputs were **not captured during the original run** and are not fabricated here.

The next evidence-hardening step is to replay sanitized representative events through the actual Wazuh 4.14.7 logtest engine and commit the resulting outputs.

## Publication policy

Raw screenshots and raw alert exports are retained outside the public repository (`evidence/raw/` is git-ignored).

Published screenshots are cropped to the Wazuh panel and redacted with solid boxes. Redacted: private IPs, hostnames, lab domain, username, agent and document IDs, GUIDs, hashes, process/thread IDs, logon ID, event record ID and `full_log`. Image metadata is not carried over.

Kept on purpose: rule fields, Sysmon image/command-line fields, alert timestamps (needed to correlate the screenshot with the JSON) and the Base64 payload, which decodes to the benign marker `Write-Output "SOC-DETECTION-TEST-TC02-V2"`.

No published artifact should be treated as evidence for an observation that was not actually produced in the controlled lab.
