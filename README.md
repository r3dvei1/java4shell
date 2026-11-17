# java4shell - CVE-2026-114938 research & reproduction kit
한국어: [README.ko.md](README.ko.md)

> **About the name.** "Java4Shell" is the *nickname the security community gave the
> vulnerability* (Oligo's write-up "Java4shell explained"), not a claim about this
> repository. This kit does **not** produce a shell. It locates the defect, reaches the
> vulnerable path, reproduces the heap corruption, and tells you whether a host is
> exposed. [docs/lab-stack.md](docs/lab-stack.md) records the attempt to turn that into
> remote execution: 1.44 million requests through nginx -> Tomcat, no shell, and the
> report says exactly why.

Independent analysis, reachability harness and environment-gate tooling for
**CVE-2026-114938**, the "Java4Shell" heap overflow in the OpenJDK **AVX-512 Base64
decode intrinsic**.

> Status: **analysis + reproduction kit.** The heap overwrite is reproduced: on a real
> AVX-512 host running the published affected build (`21.0.13.0.3`) the crafted input
> corrupts the heap and crashes the JVM in **3 of 4 attempts**, and the crash disappears
> with `-XX:-UseBASE64Intrinsics`. No weaponised RCE chain is included. See
> [docs/results.md](docs/results.md), [docs/lab-report.md](docs/lab-report.md) and
> [docs/lab-stack.md](docs/lab-stack.md).

> **Correction (2026-11-18).** Earlier revisions of this file described the trigger as
> ">128 bytes". The published trigger is `"A"×64 + "="` (**65 bytes**) on 21/25/27 and
> `"A"×128 + "="` (129 bytes) on 17. The discoverer (Calif.io) demonstrates pre-auth RCE
> against Keycloak, Jira, Confluence, Jenkins, Artifactory and PingFederate; **9.2 is the
> CVSS 4.0 score from the discoverer, 8.1 is Oracle's CVSS 3.1 score** — both are real.
> See [docs/correction-2026-11-18.md](docs/correction-2026-11-18.md).

---

## TL;DR

| | |
|---|---|
| Component | `hotspot/compiler` - AVX-512 VBMI Base64 **decode stub** |
| CWE | CWE-122 (heap-based buffer overflow) |
| CVSS 3.1 | 8.1 `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` (AC:H = difficult) |
| Affected | 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3 (+ GraalVM equivalents) |
| Fixed | 17u `jdk-17.0.21.1` and later out-of-cycle builds (8u / 11u not affected) |
| Upstream fix | `8393212: Base64 optimization improvements` - **4 lines** in `src/hotspot/cpu/x86/stubGenerator_x86_64.cpp` |
| Hardware gate | CPU must expose `avx512vbmi` **and** `avx512bw`; JVM must have `UseAVX=3` and `UseBASE64Intrinsics=true` |
| Reachability | `Base64` decode of >128 bytes, non-MIME, single call |

## The defect in one paragraph

`generate_base64_decodeBlock()` enters the vectorised path when `length > 128` and
`isMIME == 0`. After the 256/64-byte block loop it reaches `L_finalBit` with 1..63 bytes
left, computes `output_size = (length / 4) * 3` and derives a store mask from it. Pre-fix,
a **padded tail shorter than one 4-char atom** (e.g. a 130-byte input ending in `==`,
which leaves a 2-byte tail) still ran that code: `output_size` becomes `0 - 1 - 1 = -2`,
the mask shift turns into "all ones", and a **full 64-byte vector store** is performed
past the destination array. Java then throws `IllegalArgumentException`
("wrong 4-byte ending unit") on the framing, so the corruption is silent.

The fix adds, at the top of the tail path:

```c
__ BIND(L_finalBit);
// A padded Base64 tail shorter than one complete block is handled by Java.
__ cmpl(length, 4);
__ jcc(Assembler::less, L_bruteForce);
```

## Quick start

```bash
# 0) is this host exposed at all? (exit 1 = exposed, 0 = not, 2 = undetermined)
bash tools/check-target.sh

# 1) Is this host even able to run the vulnerable path?
bash tools/gate.sh

# 2) Drive the vulnerable decode path (no crash is the expected outcome)
java src/Base64Trigger.java 100000

# 3) Control run: scalar path, the same inputs
java -XX:-UseBASE64Intrinsics src/Base64Trigger.java 100000
```

### One entry point

```bash
./java4shell gate                      # hardware + JVM gate for every JDK on the host
./java4shell selftest 100000           # local reachability driver
./java4shell probe --url URL --mode auth    # remote reachability probe
./java4shell --target URL --param b --attempts 5000   # remote trigger run
./java4shell serve 8080                     # local demo decode service (src/DecodeServer.java)
```

Requirements: bash, and either a JDK on `PATH` or Docker (the launcher then uses
`eclipse-temurin:17.0.21_9-jdk`). With the Docker fallback, a target bound to the host is
reached as `host.docker.internal` instead of `127.0.0.1`.

**There is no `./java4shell https://target` attack command.** This kit ships no remote
exploit: the primitive is a silent 64-byte heap overwrite in an x86 intrinsic, a working
chain needs heap grooming, and remote reachability additionally requires the target to
feed attacker-controlled Base64 (>128 bytes, bad padded tail) into the decoder. The
`probe` subcommand only reports whether an application appears to decode our input - it
cannot distinguish a patched from an unpatched JVM, because both answer identically.

`tools/gate.sh` prints, per JDK on the box:

```
avx512vbmi: present|absent
UseAVX=3  UseBASE64Intrinsics=true
=> Base64/AVX-512 path: ACTIVE | inactive
```

If `avx512vbmi` is absent, the stub is **never generated** and this vulnerability cannot
be triggered on that CPU regardless of JDK version.

## Repository layout

```
src/Base64Trigger.java      reachability driver (crafted lengths, reports outcomes)
tools/gate.sh               CPU/JVM gate check for every JDK on the host
research/Base64OobProbe.java  instrumentation attempt (inconclusive - see results)
docs/analysis.md            code-level root cause + the exact fix
docs/detection.md           detection, inventory and mitigation guidance
docs/results.md             what we measured, on which builds, and what is NOT proven
```

## What is *not* here

* No heap grooming, no control-flow hijack, no shellcode - a 64-byte overwrite past a
  `byte[]` is a primitive, not an exploit.
* No claim that the attacker path is automatic: `AC:H` is real. Server-side code must
  feed attacker-controlled Base64 (>128 bytes, non-MIME) into the decoder, and the
  destination must be neighbours with something worth corrupting.

## References

* Oracle advisory: <https://www.oracle.com/security-alerts/cspunov2026.html>
* OpenJDK vulnerability advisory 2026/11/17: <https://openjdk.org/groups/vulnerability/advisories/2026-11-17>
* CVE record: <https://www.cve.org/CVERecord?id=CVE-2026-114938>
* Upstream commit (17u): `8ea73158afc9f2c62f72df68beb8723032bf695e` - `8393212: Base64 optimization improvements`

## License

MIT - see [LICENSE](LICENSE). Use only on systems you own or are authorised to test.


