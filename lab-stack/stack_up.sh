#!/usr/bin/env bash
# stack_up.sh - nginx (web) -> Tomcat 10 (WAS) with the decode servlet, on the vulnerable JDK.
set -eu
SRC_DIR=${1:-$HOME/lab-stack}
WAR=/tmp/dec.war
BASE=/srv/tc
NAME=dec

echo "== install =="
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nginx tomcat10 >/dev/null 2>&1 || {
  echo "apt failed"; exit 1; }

echo "== build war =="
WORK=$(mktemp -d)
mkdir -p "$WORK/WEB-INF/classes" "$WORK/WEB-INF/lib"
SERVLET_JAR=$(ls /usr/share/java/tomcat10-servlet-api*.jar 2>/dev/null | head -1)
[ -n "${SERVLET_JAR:-}" ] || SERVLET_JAR=$(find /usr/share/tomcat10 /usr/share/java -name 'servlet-api*.jar' 2>/dev/null | head -1)
echo "servlet-api: ${SERVLET_JAR:-not found}"
javac -cp "$SERVLET_JAR" -d "$WORK/WEB-INF/classes" "$SRC_DIR/DecodeServlet.java"
cp "$SRC_DIR/web.xml" "$WORK/WEB-INF/web.xml"
( cd "$WORK" && jar cf "$WAR" . )

echo "== tomcat base =="
sudo rm -rf "$BASE"
sudo mkdir -p "$BASE"/{conf,logs,temp,work,webapps}
sudo cp -r /etc/tomcat10/* "$BASE/conf/" 2>/dev/null || true
sudo cp "$WAR" "$BASE/webapps/dec.war"
sudo chown -R ubuntu:ubuntu "$BASE"

echo "== tomcat jvm options (vulnerable build, small heap for layout experiments) =="
cat > "$BASE/conf/jvm.options" <<'EOF'
-Xms256m
-Xmx512m
-XX:+UseSerialGC
EOF

echo "== start tomcat =="
export CATALINA_HOME=/usr/share/tomcat10 CATALINA_BASE=$BASE JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
"$CATALINA_HOME/bin/catalina.sh" stop >/dev/null 2>&1 || true
sleep 1
nohup "$CATALINA_HOME/bin/catalina.sh" run >"$BASE/logs/stdout.log" 2>&1 &
sleep 8

echo "== nginx config (web -> was) =="
sudo tee /etc/nginx/sites-available/java4shell >/dev/null <<'EOF'
server {
    listen 80 default_server;
    server_name _;
    client_max_body_size 4m;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 30s;
    }
}
EOF
sudo rm -f /etc/nginx/sites-enabled/default
sudo ln -sf /etc/nginx/sites-available/java4shell /etc/nginx/sites-enabled/java4shell
sudo nginx -t >/dev/null 2>&1 && sudo systemctl restart nginx

echo
echo "== verify =="
echo "jdks: $(java -version 2>&1 | head -1)"
echo -n "tomcat direct /dec/health : "; curl -s -m 5 http://127.0.0.1:8080/dec/health || echo FAIL
echo
echo -n "nginx  ->  was   /dec/health : "; curl -s -m 5 http://127.0.0.1/dec/health || echo FAIL
echo
echo -n "decode 5B b64 via nginx      : "; curl -s -m 5 "http://127.0.0.1/dec/decode?b=aGVsbG8=" || echo FAIL
echo
echo "nginx: $(nginx -v 2>&1)"
echo "java procs:"; pgrep -af 'catalina|tomcat' | head -3
