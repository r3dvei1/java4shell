# Correction — 2026-11-18: the published trigger is 65 bytes on 21/25/27

This repository's earlier result ("trigger reachable, no observable corruption at 1.44 M
requests") used a **130-byte** input with a two-character padding tail on **21.0.13**.
That is not the trigger the discoverer published.

## What the disclosure says

* Discoverer: **Quang Luong / Calif.io** (AI-assisted research), disclosure at
  <https://calif.io/java4shell/>.
* Trigger strings:

  | JDK line | Input |
  |---|---|
  | 21, 25, 27 | `"A" × 64 + "="` → **65 bytes** |
  | 17 (17.0.6+) | `"A" × 128 + "="` → **129 bytes** |

* Mechanism: `output_size = (len / 4) * 3` then `-= padding` → **-1**; `bzhiq` takes the
  index as unsigned [7:0], so 255 exceeds the register width and no mask bits are cleared.
  The `VMOVDQU8` store writes **all 64 bytes**, i.e. up to 62 bytes past the destination.
* CWE-191 (integer underflow) → CWE-122 (heap buffer overflow).
* Scores: **CVSS 4.0 9.2 (Calif)** and **CVSS 3.1 8.1 (Oracle)**. Both are real; they are
  different scoring systems, not a contradiction. The Oracle CNA record carries only the
  3.1 8.1 vector with `AC:H`.
* Pre-auth RCE demonstrated against **Keycloak, Jira, Confluence, Jenkins, Artifactory and
  PingFederate**; post-auth against Kafka, Solr, Elasticsearch, Gerrit, Spinnaker.
  Exploitation needs per-target heap grooming (G1 TLAB control, allocation warm-up), so
  there is no universal one-shot exploit — which is what `AC:H` describes.

## Re-verification on this host (21.0.13, AVX-512 VBMI)

`research/Calif65.java` uses the published 65-byte string, an exact-signature
`MethodHandle` (no boxing), a 48-byte destination and a 64-byte neighbour, and reads the
neighbour's header words through `sun.misc.Unsafe`:

```
jdk=21.0.13  src=65 bytes  dst=48 bytes
warmup done
run 0 ret=47 len 64->1771742825 CHANGED klass 00002318->9aa6699a CHANGED
run 1 ret=47 len 64->1771742825 CHANGED klass 00002318->9aa6699a CHANGED
run 2 ret=47 len 64->1771742825 CHANGED klass 00002318->9aa6699a CHANGED
run 3 ret=47 len 64->1771742825 CHANGED klass 00002318->9aa6699a CHANGED
survived
```

4/4 deterministic: the adjacent object's **length** and **klass** words are overwritten.
So the published trigger reproduces here; the earlier negative result was a wrong-input
artefact, not a property of the bug.

## Why the nginx → Tomcat campaign still did not crash

Reported by Blackpoint and consistent with our runs: whether the overwrite is _observable_
depends on collector and placement — with **G1**, crashes needed ~4,097-character inputs;
with **Serial**, 129–131 characters sufficed. Our campaign used a 130-byte body under
Serial against an application whose destination array was still followed by free TLAB space,
so the store landed in unallocated memory. The corruption was real on every request; it just
had nothing live to damage.

**Therefore:** the vulnerability is a genuine pre-auth RCE class bug (9.2 under CVSS 4.0,
8.1 under CVSS 3.1), demonstrated end-to-end by the discoverer against named products.
Treat affected builds as critical; this repository's measured "no remote crash" result is a
statement about one application's heap layout, not about the vulnerability's severity.

## Sources

* Calif disclosure — <https://calif.io/java4shell/>
* Public PoC / detection toolkit — <https://github.com/ikow/java4shell-poc>
* OpenJDK advisory 2026/11/17 — <https://openjdk.org/groups/vulnerability/advisories/2026-11-17>
* Upstream fix — `8393212: Base64 optimization improvements`
* Datadog Security Labs — <https://securitylabs.datadoghq.com/articles/java4shell-remote-code-execution-in-openjdk-cve-2026-114938/>
* Blackpoint Cyber (GC/layout dependence) — <https://blackpointcyber.com/blog/java4shell-cve-2026-114938-java-base64-decoder-flaw/>
* Wiz — <https://www.wiz.io/blog/cve-2026-114938-rce-java4shell-openjdk>
