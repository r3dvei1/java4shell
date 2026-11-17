# Naming

The repository is called java4shell because that is the community nickname for
CVE-2026-114938 (Oligo: "Java4shell explained"). It is **not** a capability claim: this
kit does not produce a shell.

Measured status behind the name:

| Claim | Evidence |
|---|---|
| vulnerable path reachable | gate + 1.44 M requests through nginx -> Tomcat (docs/lab-stack.md) |
| heap corruption | local probe: 3/4 JVM crashes; 6/6 deterministic length+klass corruption of an adjacent object (docs/results.md) |
| remote crash / DoS | not observed at 1.44 M requests |
| remote RCE / shell | **not achieved** |

If the name should match the deliverable instead of the CVE, the same tree works as
cve-2026-114938-kit / 64tail-lab: no code refers to the directory name, only the
CLI launcher (java4shell) and the docs do.
