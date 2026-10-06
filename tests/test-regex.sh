#!/usr/bin/env bash
set -euo pipefail

pattern='(?i)powershell\.exe.*\s-enc\s+[A-Za-z0-9+/]{8,}={0,2}(?:\s|$)'

positive=(
  '"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -enc VwByAGkAdABlAA=='
  'powershell.exe -NoProfile -ENC VwByAGkAdABlAA=='
  # Real TC-02-V2 command line observed in Wazuh (evidence/lab-det-001/tc02-v2-custom-alert-sanitized.json)
  '"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFMATwBDAC0ARABFAFQARQBDAFQASQBPAE4ALQBUAEUAUwBUAC0AVABDADAAMgAtAFYAMgAiAA=='
)

negative=(
  'powershell.exe -NoProfile -enc'
  'powershell.exe -NoProfile -encoding UTF8'
  'powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAA=='
  'powershell.exe -NoProfile -enc AAA'
  'powershell.exe -NoProfile -enc INVALID_*'
)

# Documented V2 coverage boundaries. These strings are not promoted to
# "expected detections": endpoint acceptance and Wazuh V3 behavior remain
# unvalidated. CI deliberately proves that the current V2 regex does NOT
# claim coverage for them.
known_v2_gap=(
  'powershell.exe -NoProfile -encod VwByAGkAdABlAA=='
  'powershell.exe -NoProfile -encodedc VwByAGkAdABlAA=='
  'powershell.exe -NoProfile -encodedco VwByAGkAdABlAA=='
  'powershell.exe -NoProfile -encodedcom VwByAGkAdABlAA=='
  'powershell.exe -NoProfile -encodedcomm VwByAGkAdABlAA=='
  'powershell.exe -NoProfile -encodedcomma VwByAGkAdABlAA=='
  'powershell.exe -NoProfile -encodedcomman VwByAGkAdABlAA=='
  'powershell.exe -NoProfile /enc VwByAGkAdABlAA=='
  'powershell.exe -NoProfile -enc "VwByAGkAdABlAA=="'
)

for sample in "${positive[@]}"; do
  if ! printf '%s\n' "$sample" | pcre2grep -q "$pattern"; then
    echo "Expected V2 positive did not match: $sample" >&2
    exit 1
  fi
done

for sample in "${negative[@]}"; do
  if printf '%s\n' "$sample" | pcre2grep -q "$pattern"; then
    echo "Expected V2 negative matched: $sample" >&2
    exit 1
  fi
done

for sample in "${known_v2_gap[@]}"; do
  if printf '%s\n' "$sample" | pcre2grep -q "$pattern"; then
    echo "Documented V2 boundary unexpectedly matched; review V3 scope: $sample" >&2
    exit 1
  fi
done

echo "PCRE2 V2 contract tests passed."
echo "Documented V2 coverage boundaries remain outside the current regex."
