/*
 * DecodeServer.java - deliberately vulnerable demo service for CVE-2026-114938 testing.
 *
 * GET /d?b=<base64>   decodes the parameter with Base64.getDecoder().decode(...)
 * GET /health         liveness probe (so a crash is observable from outside)
 *
 * It performs no length validation, which is exactly the "web service that supplies
 * data to the Base64 API" scenario in the CVE description. Run it on an affected JDK
 * whose CPU exposes avx512vbmi to reproduce the vector tail path.
 *
 *   java DecodeServer.java 8080
 */
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.Executors;

public class DecodeServer {

    private static final Base64.Decoder DEC = Base64.getDecoder();

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8080;
        HttpServer s = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 128);
        s.createContext("/health", ex -> reply(ex, 200, "ok"));
        s.createContext("/d", DecodeServer::decode);
        s.setExecutor(Executors.newFixedThreadPool(8));
        s.start();
        System.out.println("[decode-server] listening on 127.0.0.1:" + port
                + " jdk=" + System.getProperty("java.version"));
    }

    private static void decode(HttpExchange ex) throws java.io.IOException {
        String q = ex.getRequestURI().getRawQuery();
        String v = null;
        if (q != null) {
            for (String kv : q.split("&")) {
                int i = kv.indexOf('=');
                if (i > 0 && kv.substring(0, i).equals("b")) {
                    v = URLDecoder.decode(kv.substring(i + 1), StandardCharsets.UTF_8);
                }
            }
        }
        if (v == null) {
            reply(ex, 400, "missing b");
            return;
        }
        try {
            byte[] out = DEC.decode(v);
            reply(ex, 200, "len=" + out.length);
        } catch (IllegalArgumentException e) {
            reply(ex, 400, "iae:" + e.getMessage());
        }
    }

    private static void reply(HttpExchange ex, int code, String body) throws java.io.IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(code, b.length);
        ex.getResponseBody().write(b);
        ex.close();
    }
}
