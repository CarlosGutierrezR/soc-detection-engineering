#!/usr/bin/env bash
set -euo pipefail

pattern='(?i)powershell\.exe.*\s-enc\s+[A-Za-z0-9+/]{8,}={0,2}(?:\s|$)'

positive=(
  '"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -enc VwByAGkAdABlAA=='
  'powershell.exe -NoProfile -ENC VwByAGkAdABlAA=='
)

negative=(
  'powershell.exe -NoProfile -enc'
  'powershell.exe -NoProfile -encoding UTF8'
  'powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAA=='
  'powershell.exe -NoProfile -enc AAA'
  'powershell.exe -NoProfile -enc INVALID_*'
)

for sample in "${positive[@]}"; do
  if ! printf '%s\n' "$sample" | pcre2grep -q "$pattern"; then
    echo "Expected positive did not match: $sample" >&2
    exit 1
  fi
done

for sample in "${negative[@]}"; do
  if printf '%s\n' "$sample" | pcre2grep -q "$pattern"; then
    echo "Expected negative matched: $sample" >&2
    exit 1
  fi
done

echo "PCRE2 contract tests passed."
