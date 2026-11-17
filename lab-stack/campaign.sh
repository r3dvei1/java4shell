#!/usr/bin/env bash
# campaign.sh - rebuild the servlet, restart the WAS, then drive the trigger through nginx.
set -u
SRC=$HOME/lab-stack
BASE=/srv/tc
WAR=/tmp/dec.war

echo "== stop duplicate system tomcat =="
sudo systemctl stop tomcat10 >/dev/null 2>&1 || true
sudo systemctl disable tomcat10 >/dev/null 2>&1 || true

echo "== rebuild war =="
WORK=$(mktemp -d)
mkdir -p "$WORK/WEB-INF/classes"
SERVLET_JAR=$(ls /usr/share/java/tomcat10-servlet-api*.jar | head -1)
javac -cp "$SERVLET_JAR" -d "$WORK/WEB-INF/classes" "$SRC/DecodeServlet.java" || exit 1
cp "$SRC/web.xml" "$WORK/WEB-INF/web.xml"
(cd "$WORK" && jar cf "$WAR" .) || exit 1

echo "== restart was =="
export CATALINA_HOME=/usr/share/tomcat10 CATALINA_BASE=$BASE JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
"$CATALINA_HOME/bin/catalina.sh" stop >/dev/null 2>&1 || true
sleep 2
pkill -f 'catalina.base=/srv/tc' >/dev/null 2>&1 || true
sleep 1
rm -rf "$BASE/webapps/dec" "$BASE/webapps/dec.war" "$BASE/work/Catalina"
cp "$WAR" "$BASE/webapps/dec.war"
nohup "$CATALINA_HOME/bin/catalina.sh" run >"$BASE/logs/stdout.log" 2>&1 &
sleep 10

echo "== verify through nginx =="
echo -n "health  : "; curl -s -m 5 http://127.0.0.1/dec/health; echo
echo -n "decode  : "; curl -s -m 5 "http://127.0.0.1/dec/decode?b=aGVsbG8="; echo
echo "pid     : $(pgrep -f 'catalina.base=/srv/tc' | head -1)"

echo
echo "== campaign through nginx (control / padded / badtail x2) =="
cd "$HOME/java4shell" || exit 1
for spec in "control 300 control" "padded 30000 padded" "badtail 100000 badtail" "badtail 100000 badtail"; do
  set -- $spec
  out=$(java src/RemoteAttack.java --target http://127.0.0.1/dec/decode --param b \
          --attempts "$2" --shape "$3" 2>&1 | grep -E '^  [a-z]' | tr '\n' ' ')
  echo "$1($2): $out"
  echo -n "   health now: "; curl -s -m 5 http://127.0.0.1/dec/health || echo DOWN
  echo
  sleep 1
done

echo "== after =="
echo -n "health : "; curl -s -m 5 http://127.0.0.1/dec/health || echo DOWN
echo
echo "hs_err : $(ls -1 $BASE/hs_err_pid*.log 2>/dev/null | tail -2 | tr '\n' ' ')"
echo "log    :"; tail -5 "$BASE/logs/stdout.log"
