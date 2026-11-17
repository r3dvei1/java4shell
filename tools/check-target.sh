#!/usr/bin/env bash
# check-target.sh - one question, one answer: is THIS host exposed to CVE-2026-114938?
#
#   ./check-target.sh            # full report, exit 1 if exposed
#   ./check-target.sh --quiet    # single verdict line only
#
# Exit codes:  0 = not exposed   1 = exposed   2 = could not decide
#
# The hardware gate is evaluated first: without AVX-512 VBMI the vulnerable stub is never
# generated, regardless of the JDK version.

set -u

QUIET=0
[ "${1:-}" = "--quiet" ] && QUIET=1

say()   { [ "$QUIET" -eq 1 ] || printf '%s\n' "$*"; }
head1() { say ""; say "== $* =="; }
verdict() { printf 'VERDICT: %s\n' "$*"; }   # always printed, even with --quiet

# ver_ge A B -> true if version A >= version B (numeric, dot separated)
ver_ge() {
  awk -v a="$1" -v b="$2" 'BEGIN{
    n=split(a,x,"."); m=split(b,y,".");
    for(i=1;i<=4;i++){ xv=(i<=n)?x[i]+0:0; yv=(i<=m)?y[i]+0:0;
      if(xv>yv) exit 0; if(xv<yv) exit 1; }
    exit 0 }'
}

# --- 1. hardware gate -----------------------------------------------------------
VBMI=0; BW=0
if [ -r /proc/cpuinfo ]; then
  grep -qm1 'avx512vbmi' /proc/cpuinfo && VBMI=1
  grep -qm1 'avx512bw'   /proc/cpuinfo && BW=1
fi
head1 "hardware gate"
say "  avx512vbmi : $([ "$VBMI" = 1 ] && echo present || echo absent)"
say "  avx512bw   : $([ "$BW"   = 1 ] && echo present || echo absent)"
say "  kernel     : $(uname -srm 2>/dev/null || echo unknown)"

if [ "$VBMI" != 1 ] || [ "$BW" != 1 ]; then
  say "  => the AVX-512 Base64 stub is never generated on this CPU"
  verdict "NOT EXPOSED (hardware gate closed)"
  exit 0
fi

# --- 2. every JVM we can find quickly -------------------------------------------
JVMS=""
for j in $(command -v java 2>/dev/null); do JVMS="$JVMS $j"; done
for d in /usr/lib/jvm/*/bin/java /usr/java/*/bin/java /opt/*/bin/java \
         /usr/share/*/jdk/bin/java /usr/local/*/bin/java /opt/java/openjdk/bin/java; do
  [ -x "$d" ] && JVMS="$JVMS $d"
done
JVMS=$(printf '%s\n' $JVMS | sort -u)

head1 "java runtimes"
EXPOSED=0
DECIDED=0
FOUND=0
for j in $JVMS; do
  FOUND=1
  raw=$("$j" -version 2>&1 | head -1)
  ver=$(printf '%s' "$raw" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  [ -n "$ver" ] || continue
  major=${ver%%.*}
  avx=$("$j" -XX:+PrintFlagsFinal -version 2>/dev/null | awk '/UseAVX /{print $4; exit}')
  b64=$("$j" -XX:+PrintFlagsFinal -version 2>/dev/null | awk '/UseBASE64Intrinsics/{print $4; exit}')
  [ -n "${avx:-}" ] || avx='?'
  [ -n "${b64:-}" ] || b64='?'

  state='unknown'
  case "$major" in
    8|9|10|11|12|13|14|15|16)
      state='not affected (line not named in the advisory)'; DECIDED=1 ;;
    17|21|25|27)
      base=''
      case "$major" in
        17) base=17.0.21.1 ;; 21) base=21.0.13.1 ;; 25) base=25.0.5.1 ;; 27) base=27.0.1.1 ;;
      esac
      if ver_ge "$ver" "$base"; then
        state='fixed build'; DECIDED=1
      elif ver_ge "$ver" 17.0.6; then
        DECIDED=1
        if [ "$avx" = 3 ] && [ "$b64" = true ]; then
          state='AFFECTED build, vulnerable path ACTIVE'; EXPOSED=1
        else
          state="AFFECTED build, but path inactive (UseAVX=$avx intrinsics=$b64)"
        fi
      else
        state='below the reported range (17.0.6+)'
      fi ;;
    *) state='version line not covered by this check' ;;
  esac

  say "  $j"
  say "    version : $ver"
  say "    flags   : UseAVX=$avx  UseBASE64Intrinsics=$b64"
  say "    state   : $state"
done
[ "$FOUND" -eq 1 ] || say "  (no java found on PATH or in the usual locations)"

# --- 3. anything running right now ----------------------------------------------
head1 "running JVMs"
JFOUND=$(pgrep -c -x java 2>/dev/null || true)
[ -n "${JFOUND:-}" ] || JFOUND=0
say "  java processes: $JFOUND"
if [ "$JFOUND" -gt 0 ]; then
  pgrep -a -x java 2>/dev/null | cut -c1-110 | sed 's/^/  /' | head -5
fi

# --- 4. verdict ------------------------------------------------------------------
if [ "$EXPOSED" = 1 ]; then
  verdict "EXPOSED - this host can run the vulnerable Base64 path"
  say "  next: patch to the fixed build, or restart the JVM with"
  say "        -XX:-UseBASE64Intrinsics   (narrow, recommended)"
  say "        -XX:UseAVX=2               (broad, affects all AVX-512 code)"
  exit 1
elif [ "$DECIDED" = 1 ]; then
  verdict "NOT EXPOSED - affected or fixed JVM found, vulnerable path inactive"
  exit 0
else
  verdict "UNDETERMINED - no JVM in the affected range found on this host"
  say "  containers and other hosts are separate: run this script inside them."
  exit 2
fi
