import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Decode endpoints for the java4shell lab stack (nginx -> Tomcat).
 *
 *   /dec/decode      Base64.decode(b)             - JDK allocates the destination
 *   /dec/decode2     Base64.decode(src, dst)      - application allocates the destination
 *   /dec/decode3     decode2 + retains the array  - forces GC to scan a corrupted header
 *   /dec/selfcheck   decode2 + reports whether the neighbouring object's header changed
 *   /dec/health      liveness probe
 */
public class DecodeServlet extends HttpServlet {

    private static final Base64.Decoder DEC = Base64.getDecoder();
    private static final List<byte[]> CACHE = new ArrayList<>();
    private static sun.misc.Unsafe U;
    private static long BASE_OFF;

    static {
        try {
            Field f = Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe");
            f.setAccessible(true);
            U = (sun.misc.Unsafe) f.get(null);
            BASE_OFF = U.arrayBaseOffset(byte[].class);
        } catch (Throwable t) {
            U = null;
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String uri = req.getRequestURI();
        if (uri != null && uri.endsWith("health")) {
            resp.setStatus(200);
            resp.getWriter().print("ok");
            return;
        }
        String b = req.getParameter("b");
        if (b == null) {
            resp.setStatus(400);
            resp.getWriter().print("missing b");
            return;
        }
        try {
            if (uri != null && (uri.endsWith("decode2") || uri.endsWith("decode3")
                    || uri.endsWith("selfcheck"))) {
                byte[] src = b.getBytes(StandardCharsets.ISO_8859_1);
                byte[] dst = new byte[(src.length / 4) * 3 + 3];
                byte[] keep = new byte[dst.length];      // neighbour of dst
                int lenBefore = U == null ? -1 : U.getInt(keep, BASE_OFF - 4);

                long t0 = System.nanoTime();
                int n = DEC.decode(src, dst);
                long us = (System.nanoTime() - t0) / 1000;

                int lenAfter = U == null ? -1 : U.getInt(keep, BASE_OFF - 4);

                if (uri.endsWith("decode3")) {
                    synchronized (CACHE) {
                        if (CACHE.size() < 400) {
                            CACHE.add(keep);
                        }
                    }
                }
                resp.setStatus(200);
                if (uri.endsWith("selfcheck")) {
                    resp.getWriter().printf("decoded=%d us=%d keep.len %d->%d %s%n",
                            n, us, lenBefore, lenAfter,
                            lenBefore == lenAfter ? "(intact)" : "** CORRUPTED **");
                } else {
                    resp.getWriter().print("len=" + n + "/" + keep.length);
                }
                return;
            }
            byte[] out = DEC.decode(b);
            byte[] copy = out.clone();
            resp.setStatus(200);
            resp.getWriter().print("len=" + copy.length);
        } catch (IllegalArgumentException e) {
            resp.setStatus(400);
            resp.getWriter().print("iae");
        }
    }
}
