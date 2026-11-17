/*
 * RemoteProbe.java - reachability probe (NOT an exploit, NOT a vulnerability scanner).
 *
 * It answers one narrow question: does the target application actually hand
 * attacker-supplied Base64 to a decoder, and does its behaviour change when the
 * input is shaped like the CVE-2026-114938 trigger (length > 128, not a multiple of 4,
 * padded tail)?
 *
 * It CANNOT tell you whether the target JVM is vulnerable: patched and unpatched
 * builds answer identically because the overflow is silent. Use tools/gate.sh on the
 * host itself for that.
 *
 * Modes:
 *   --mode auth    Authorization: Basic <base64>
 *   --mode query   ?<param>=<base64>
 *   --mode body    POST body <param>=<base64> (x-www-form-urlencoded)
 *
 * Usage:
 *   java RemoteProbe.java --url https://host/path --mode auth
 *   java RemoteProbe.java --url https://host/path --mode query --param token
 */
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;

public class RemoteProbe {

    // 130 chars: >128 (enters the vector path) and %4 != 0 (leaves a 2-byte tail)
    private static String crafted() {
        char[] c = new char[130];
        Arrays.fill(c, '/');
        c[128] = '=';
        c[129] = '=';
        return new String(c);
    }

    private static String paddedValid() {
        char[] c = new char[128];
        Arrays.fill(c, '/');
        return new String(c) + "==";      // 130 chars, still %4 = 2 -> invalid framing
    }

    private static String shortValid() {
        return Base64.getEncoder().encodeToString("probe".getBytes());
    }

    public static void main(String[] args) throws Exception {
        String url = null, mode = "auth", param = "data";
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--url" -> url = args[++i];
                case "--mode" -> mode = args[++i];
                case "--param" -> param = args[++i];
                default -> { }
            }
        }
        if (url == null) {
            System.out.println("usage: RemoteProbe --url URL [--mode auth|query|body] [--param name]");
            return;
        }

        System.out.println("target=" + url + " mode=" + mode);
        System.out.println("note: a status/latency difference only shows the app decodes Base64;");
        System.out.println("      it says nothing about the target JVM being vulnerable.");
        System.out.println();

        String[] labels = {"control-short-valid", "crafted-130-badtail", "padded-130-badtail"};
        String[] values = {shortValid(), crafted(), paddedValid()};

        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(8))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        for (int i = 0; i < values.length; i++) {
            HttpRequest req = build(url, mode, param, values[i]);
            long t0 = System.nanoTime();
            try {
                HttpResponse<String> r = client.send(req, HttpResponse.BodyHandlers.ofString());
                long ms = (System.nanoTime() - t0) / 1_000_000;
                String body = r.body() == null ? "" : r.body().replaceAll("\\s+", " ");
                System.out.printf("  %-20s %3d %5dms %s%n", labels[i], r.statusCode(), ms,
                        body.substring(0, Math.min(60, body.length())));
            } catch (Exception e) {
                long ms = (System.nanoTime() - t0) / 1_000_000;
                System.out.printf("  %-20s ERR %5dms %s%n", labels[i], ms, e.getClass().getSimpleName());
            }
        }
    }

    private static HttpRequest build(String url, String mode, String param, String value) {
        HttpRequest.Builder b = HttpRequest.newBuilder().timeout(Duration.ofSeconds(10))
                .header("User-Agent", "java4shell-probe/1.0");
        switch (mode) {
            case "auth" -> b.uri(URI.create(url)).GET()
                    .header("Authorization", "Basic " + value);
            case "query" -> {
                String sep = url.contains("?") ? "&" : "?";
                b.uri(URI.create(url + sep + param + "=" + value)).GET();
            }
            default -> b.uri(URI.create(url))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(param + "=" + value));
        }
        return b.build();
    }
}
