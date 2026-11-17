#!/usr/bin/env bash
# CPU / JVM gate for CVE-2026-114938 (AVX-512 VBMI Base64 decode stub)
# Read-only. Works on Linux. macOS: use `sysctl -a | grep machdep.cpu.features`.
set -u

echo "# java4shell gate check - $(hostname) $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo

echo "## CPU flags"
for f in avx512f avx512bw avx512vl avx512vbmi avx512_vbmi2; do
  if grep -qm1 "$f" /proc/cpuinfo 2>/dev/null; then echo "  $f: present"; else echo "  $f: absent"; fi
done
if grep -qm1 'avx512vbmi' /proc/cpuinfo 2>/dev/null; then
  VBMI=1
  echo "  => VBMI present: the AVX-512 Base64 stub can be generated"
else
  VBMI=0
  echo "  => VBMI absent: the stub is NEVER generated -> not exploitable on this CPU"
fi
echo

echo "## JVMs"
for j in $( { command -v java 2>/dev/null; find / -xdev -maxdepth 6 -name java -type f -path '*/bin/java' 2>/dev/null; } | sort -u | head -8 ); do
  [ -x "$j" ] || continue
  echo "### $j"
  "$j" -version 2>&1 | head -1 | sed 's/^/  /'
  avx=$("$j" -XX:+PrintFlagsFinal -version 2>/dev/null | awk '/UseAVX /{print $4; exit}')
  b64=$("$j" -XX:+PrintFlagsFinal -version 2>/dev/null | awk '/UseBASE64Intrinsics/{print $4; exit}')
  echo "  UseAVX=${avx:-?}  UseBASE64Intrinsics=${b64:-?}"
  if [ "$VBMI" = "1" ] && [ "${avx:-0}" = "3" ] && [ "${b64:-false}" = "true" ]; then
    echo "  => Base64/AVX-512 path: ACTIVE (vulnerable code path reachable)"
  else
    echo "  => Base64/AVX-512 path: inactive"
  fi
done
echo

echo "## Version range (reported affected: 17.0.21.0.3 / 21.0.13.0.3 / 25.0.5.0.3 / 27.0.1.0.3)"
java -version 2>&1 | head -1 | sed 's/^/  /'
echo "  patch level must move past the builds above (e.g. 17.0.21.1+, 21.0.13.0.4+)"
