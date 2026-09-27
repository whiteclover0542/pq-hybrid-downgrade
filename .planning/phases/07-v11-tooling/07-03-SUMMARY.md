---
phase: 07-v11-tooling
plan: 03
status: complete
completed: 2026-09-25
---

# v1.1 P3 Analysis Summary

## Evidence used

[확실] P3 recomputed its counts only from the 90 JSON records in `docs/research/baselines/raw/v1.1/`. Every one of the nine valid implementation/condition combinations has r01 through r10 exactly once, and all records have `manipulation_verified=true`.

[확실] The direct aggregation is documented in [v1.1-p3-analysis.md](../../../docs/research/v1.1-p3-analysis.md). It reports 10/10 successful classical TLS negotiations without recorded HRR for each of OpenSSL and BoringSSL in `silent-downgrade`, 10/10 verified TLS failures per implementation in `onpath-strip`, and zero automatic downgrade flags in the final data.

## Interpretation boundary

[확실] P3 records a scoped cross-implementation observation: in the tested group order and audit definition, advertised hybrid support was followed by a successful classical TLS negotiation without recorded HRR or automatic flag.

[불확실] The result alone does not determine RFC non-conformance, exploitability, a CVE, or behavior outside the tested versions and loopback environment. OpenSSH's on-path result is retained as a failed structural control, not as a successful downgrade.

## Handoff

[확실] P3 is complete. `docs/PAPER.md`, the reproduction package, and v1.0 historical outputs were not changed. P4 is the next phase and may update those deliverables only after using this bounded P3 analysis.
