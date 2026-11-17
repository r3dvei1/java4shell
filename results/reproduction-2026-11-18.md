# Reproduction evidence - CVE-2026-114938

Host: PVE VM java4shell (Ryzen 7 PRO 8845HS, vx512vbmi present), Ubuntu 24.04.4,
openjdk 21.0.13.0.3+1-1~24.04.1-Ubuntu (published affected build).

Probe: esearch/Base64OobProbe2.java (reflection call to Base64.decodeBlock,
all arguments pre-allocated, destination array 96 bytes, input 130 bytes ending in ==).

| attempt | flags | outcome |
|---|---|---|
| 1 | default | JVM crash - hs_err_pid1431.log |
| 2 | default | JVM crash - hs_err_pid1647.log |
| 3 | default | JVM crash - hs_err_pid1674.log |
| 4 | default | no write observed (heap layout) |
| control | -XX:-UseBASE64Intrinsics | changed=0 ff=0, no crash |

Crash excerpt:

```
#  SIGSEGV (0xb) at pc=0x000072621bd53020, pid=1431, tid=1433
# Problematic frame:
# j  sun.invoke.util.ValueConversions.unboxInteger(Ljava/lang/Object;Z)I+1  java.base@21.0.13.0.3
siginfo: si_signo: 11 (SIGSEGV), si_code: 1 (SEGV_MAPERR), si_addr: 0x0000726251a669da
```

Interpretation: the fault is *downstream* of the store. The JVM dereferences the object
that the 64-byte vector store corrupted, while unboxing the reflected return value.
Disabling the intrinsic makes both the corruption and the crash disappear.

Rate: **3/4 (75 %)** on this host, layout dependent - consistent with CVSS AC:H.

Full hs_err logs are kept with the private lab notes (they contain host paths and
addresses); the excerpt above is the reproducible part.
