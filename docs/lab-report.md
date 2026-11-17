# Lab report — real AVX-512 host (PVE VM)

Date: 2026-11-17/18 UTC. Purpose: run the CVE-2026-114938 reproducer on a host whose
CPU actually exposes the AVX-512 Base64 stub, using the **published affected build**.

## Host

| | |
|---|---|
| VM | `java4shell` on Proxmox VE 9.2.11 (QEMU 11.0), CPU type `host` |
| Physical CPU | AMD Ryzen 7 PRO 8845HS (Zen 4 / Hawk Point) |
| Guest | Ubuntu 24.04.4 LTS, kernel 6.8.0-106-generic, 2 vCPU, 3 GiB RAM |
| JDK | `openjdk 21.0.13.0.3+1-1-24.04.1-Ubuntu` (listed as affected in the CVE record) |

## Gate

```
avx512f: present   avx512bw: present   avx512vl: present
avx512vbmi: present   avx512_vbmi2: present
=> VBMI present: the AVX-512 Base64 stub can be generated

UseAVX=3   UseBASE64Intrinsics=true
=> Base64/AVX-512 path: ACTIVE (vulnerable code path reachable)
```

So the three conditions that a VM must satisfy (CPU bit, JVM flag, JDK version) all hold:
this is a genuine reproduction environment, not a proxy.

## Runs (`src/Base64Trigger.java`)

| run | command | result |
|---|---|---|
| 50k, intrinsic on | `java src/Base64Trigger.java 50000` | `decoded=33333 rejected=16667 unexpected=0` |
| 50k, intrinsic off (control) | `java -XX:-UseBASE64Intrinsics ... 50000` | same counters |
| 500k, 128 MiB heap, SerialGC | `java -Xmx128m -XX:+UseSerialGC ... 500000` | `decoded=333333 rejected=166667 unexpected=0`, 0.52 s, RSS 98 MB |
| 2k, interpreter only | `java -Xint ... 2000` | same counters |

No crash, no unexpected exception in ~600k decodes. That is the documented behaviour of
this bug: the 64-byte overwrite is silent, Java only reports the invalid framing.

## What this proves / does not prove

| Claim | Status |
|---|---|
| The vulnerable stub is generated and reachable on this host | **proven** (gate + runs) |
| The affected public build reproduces the code path | **proven** |
| A 64-byte write lands past the destination array | **not observed** (silent; needs fixed-build diff or native instrumentation) |
| Remote exploitation / RCE | **not attempted** |

## Next steps (in order of value)

1. **Fixed build differential** — install `21.0.13.0.4+` (or Temurin `17.0.21.1+`) when
   published, run the same driver, and confirm the tail branch is no longer taken
   (`-XX:+PrintAssembly` on the build that contains `8393212` shows the `length < 4`
   guard before the vector store).
2. **Native instrumentation** — `gdb` with a breakpoint on the generated stub body and a
   watchpoint placed on the destination array end; requires ≥8 GiB RAM for a comfortable
   JVM + debugger session (this VM has 3 GiB, enough for the driver only).
3. **Heap-shaping research** — only after 1 or 2 gives a deterministic signal.

## Reproduction of the heap corruption (added after the 8 GiB upgrade)

Probe `research/Base64OobProbe2.java` on `21.0.13.0.3` with all reflection arguments
pre-allocated:

| attempt | JVM flags | outcome |
|---|---|---|
| 1 | default | JVM crash (hs_err_pid1431) |
| 2 | default | JVM crash (hs_err_pid1647) |
| 3 | default | JVM crash (hs_err_pid1674) |
| 4 | default | no write observed (layout dependent) |
| control | -XX:-UseBASE64Intrinsics | no write, no crash |

Crash: SIGSEGV, si_addr garbage, problematic frame
`sun.invoke.util.ValueConversions.unboxInteger` — the JVM dereferences the object that
the 64-byte store corrupted, immediately after the decode call returns.

3/4 = 75 % on this host. Layout dependent, consistent with CVSS AC:H.
