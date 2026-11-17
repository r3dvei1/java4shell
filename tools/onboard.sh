#!/usr/bin/env bash
# onboard.sh - collect everything needed to judge a host for CVE-2026-114938.
# Run this on the machine you want to test (the AVX-512 box, the build host, ...).
#
#   bash tools/onboard.sh [report.md]
#
# Output is a single markdown file you can paste into an issue / hand back for review.
set -u
DIR=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-onboard-report.md}

{
  echo "# java4shell onboard report"
  echo
  echo "- host: $(hostname)"
  echo "- utc: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "- kernel: $(uname -srm 2>/dev/null || echo unknown)"
  echo
  echo "## CPU"
  if [ -r /proc/cpuinfo ]; then
    for f in avx512f avx512bw avx512vl avx512vbmi avx512_vbmi2; do
      if grep -qm1 "$f" /proc/cpuinfo; then echo "- $f: present"; else echo "- $f: absent"; fi
    done
    grep -m1 'model name' /proc/cpuinfo | sed 's/^/- /'
  else
    echo "- /proc/cpuinfo not readable"
  fi
  echo
  echo "## Gate"
  echo '```'
  bash "$DIR/tools/gate.sh" 2>&1
  echo '```'
  echo
  echo "## Reachability driver (20k iterations)"
  echo '```'
  if command -v java >/dev/null 2>&1; then
    java "$DIR/src/Base64Trigger.java" 20000 2>&1 | tail -6
  else
    echo "java not found on this host"
  fi
  echo '```'
  echo
  echo "## Notes"
  echo "- what you expected to test (patched vs unpatched build):"
  echo "- JDK distribution + exact version under test:"
  echo "- anything the gate reported as surprising:"
} | tee "$OUT"

echo
echo "[onboard] written to $OUT"
