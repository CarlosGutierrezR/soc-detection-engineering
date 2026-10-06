# LAB-DET-001 — Test Cases

All payloads were benign and executed only inside the authorized SOC lab.

| Test | Purpose | Controlled behavior | Expected classification | Observed result |
|---|---|---|---|---|
| TC-00 | Baseline | PowerShell without encoded argument | Generic PowerShell only | `92027`, level 4 |
| TC-01 | Native positive | `-EncodedCommand <BASE64>` | Native encoded-command alert | `92057`, level 12 |
| TC-02 | Gap reproduction | `-enc <BASE64>` before custom rule | Determine native handling | `92027`, level 4 |
| TC-02-R1 | Custom V1 positive | valid `-enc <BASE64>` | Custom encoded-command alert | `100100`, level 12 |
| NEG-V1 | V1 negative | `-enc` with no argument | No encoded-command alert | `100100`, level 12 — false positive |
| TC-02-V2 | Final positive | valid `-enc <BASE64>` | Custom encoded-command alert | `100100`, level 12 — PASS |
| NEG-V2 | Final negative | `-enc` with no argument | No custom encoded-command alert | `92027`, level 4; no `100100` — PASS |

## Final rule status

The V2 rule passed the controlled positive and negative acceptance tests.

No claim is made that this small test set represents a production false-positive rate.
