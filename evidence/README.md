# Evidence — LAB-DET-001

Raw screenshots and full SOC logs are intentionally not committed to this public portfolio repository because they may contain lab addressing, host metadata, usernames, hashes, timestamps, or other operational details.

The repository records sanitized, reproducible evidence in the documentation and test matrix.

## Evidence manifest

| Evidence item | Result captured |
|---|---|
| Native baseline | normal PowerShell -> `92027` / level 4 |
| Native encoded command | `-EncodedCommand` -> `92057` / level 12 |
| Native coverage gap | `-enc` -> `92027` / level 4 |
| Native-rule inspection | rule `92057` regex omitted exact `enc` token |
| Custom V1 positive | valid `-enc <BASE64>` -> `100100` / level 12 |
| V1 false positive | empty `-enc` -> `100100` / level 12 |
| V2 positive | valid `-enc <BASE64>` -> `100100` / level 12 |
| V2 negative | empty `-enc` -> native `92027` / level 4; no `100100` |
| Wazuh validation | `wazuh-analysisd -t` returned exit code 0 |
| Manager health | Wazuh Manager active after restart |

Raw evidence is retained outside the public repository. Any future screenshots added here must be sanitized before publication.
