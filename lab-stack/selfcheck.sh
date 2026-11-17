#!/usr/bin/env bash
# selfcheck.sh - remote-observable corruption test.
set -u
SRC=$HOME/lab-stack
BASE=/srv/tc
WORK=$(mktemp -d)
mkdir -p "$WORK/WEB-INF/classes"
SERVLET_JAR=$(ls /usr/share/java/tomcat10-servlet-api*.jar | head -1)
javac -nowarn -cp "$SERVLET_JAR" -d "$WORK/WEB-INF/classes" "$SRC/DecodeServlet.java" || exit 1
cp "$SRC/web.xml" "$WORK/WEB-INF/web.xml"
(cd "$WORK" && jar cf /tmp/dec.war .) || exit 1

export CATALINA_HOME=/usr/share/tomcat10 CATALINA_BASE=$BASE JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
"$CATALINA_HOME/bin/catalina.sh" stop >/dev/null 2>&1 || true
sleep 2
pkill -f 'catalina.base=/srv/tc' >/dev/null 2>&1 || true
sleep 1
rm -rf "$BASE/webapps/dec" "$BASE/webapps/dec.war" "$BASE/work/Catalina"
cp /tmp/dec.war "$BASE/webapps/dec.war"
nohup "$CATALINA_HOME/bin/catalina.sh" run >"$BASE/logs/stdout.log" 2>&1 &
sleep 10

PAYLOAD=$(printf '/%.0s' $(seq 1 128))"=="
echo "payload length: ${#PAYLOAD}"
echo
echo "== control (valid short) =="
curl -s -m 5 "http://127.0.0.1/dec/selfcheck?b=aGVsbG8="
echo
echo "== crafted badtail x5 =="
for i in 1 2 3 4 5; do
  curl -s -m 5 "http://127.0.0.1/dec/selfcheck?b=${PAYLOAD}"
done
echo
echo "== 3-arg decode sanity (decode2) =="
curl -s -m 5 "http://127.0.0.1/dec/decode2?b=aGVsbG8="
echo
echo "hs_err: $(ls -1 "$BASE"/hs_err_pid*.log 2>/dev/null | tail -2 | tr '\n' ' ')"
