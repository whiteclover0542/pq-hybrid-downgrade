# Requirements (from PRDs)

Source PRD: D:\sr\pq-hybrid-downgrade\docs\PROPOSAL.md
Title: 연구 기획서 — 포스트퀀텀 하이브리드 키 교환의 다운그레이드 저항성 (증명된 설계와 실제 구현 사이의 간극)

Central hypothesis: Hybrid PQ key-exchange downgrade resistance is formally proven at the protocol-design level; this project empirically tests whether deployed implementations actually honor that proof, and whether negotiation-logic downgrade is a single-library bug or a cross-implementation pattern.

---

## REQ-hypothesis-lock

- source: D:\sr\pq-hybrid-downgrade\docs\PROPOSAL.md (§1, §3)
- scope: research framing
- description: Fix a testable hypothesis and research question distinguishing "proven-safe design" from "as-deployed safe", scoped to whether negotiation-logic flaws leading to hybrid-PQ downgrade are an accidental single-library bug or a general pattern across implementations.
- acceptance criteria:
  - Hypothesis is stated in one sentence showing what affects what.
  - The research question narrows to bug-vs-pattern across independent codebases.

## REQ-prior-work-verification

- source: D:\sr\pq-hybrid-downgrade\docs\PROPOSAL.md (§3), docs\plans\phase-1-literature.md
- scope: literature grounding
- description: Verify existence of prior work on downgrade-resistant hybrid PQ combiners (Bhargavan et al. downgrade-resistance definition; "Transcript-Bound Combiners for Downgrade-Resilient Hybrid PQ Key Establishment", 2026-09) and analyze the baseline case CVE-2026-2673 at source level (OpenSSL advisory, affected versions, flaw mechanism). Re-check the three background CVEs (FreeRDP CVE-2026-91949, Cisco CVE-2026-20249, NGINX+OpenSSL CVE-2026-90439) on NVD.
- acceptance criteria:
  - At least one empirically/data-verified prior study is listed.
  - Known facts vs. this project's new claims are separated.
  - Every cited work passed existence verification with method recorded; hallucinated/mismatched works excluded with reason.

## REQ-testbed-three-implementations

- source: D:\sr\pq-hybrid-downgrade\docs\PROPOSAL.md (§4.2, §5.1), docs\plans\phase-2-testbed.md
- scope: experiment environment
- description: Build three independent hybrid-KEM codebases locally and capture a normal (unmanipulated) hybrid-handshake baseline for each: OpenSSL + oqs-provider (X25519MLKEM768; CVE-2026-2673 target line), BoringSSL (X25519Kyber768), OpenSSH (sntrup761x25519-sha512).
- acceptance criteria:
  - All three implementations complete a hybrid handshake with no manipulation.
  - Negotiated group is observable in logs for each implementation.
  - Version / commit hash / build options recorded for reproduction.
  - Audit/logging paths confirmed (SSLKEYLOGFILE, s_server -state, sshd -vvv, Wireshark capture).

## REQ-fault-injector

- source: D:\sr\pq-hybrid-downgrade\docs\PROPOSAL.md (§4.1, §4.3), docs\plans\phase-3-tooling.md
- scope: tooling
- description: Build a man-in-the-middle Fault Injector that intercepts the TLS record layer and manipulates negotiation fields, plus a results-collection harness. Two fault types: (1) group-list manipulation — remove/reorder hybrid groups in supported_groups/KEX list to induce classical-only fallback; (2) combiner-binding violation — fill only one of the two hybrid components (classical/PQ) with a real value and forge the other, testing whether transcript-binding verification rejects it. Tools: Python (scapy or s_client/s_server low-level hooking), optionally mitmproxy-style proxy extended for TLS record manipulation.
- acceptance criteria:
  - Both fault types can be applied to each of the three implementations.
  - A verification script confirms manipulation actually took effect (distinguishing tool bugs from real "no flaw" results).
  - Each run auto-records the three observation metrics into structured raw data.

## REQ-repeated-execution

- source: D:\sr\pq-hybrid-downgrade\docs\PROPOSAL.md (§5.2, §5.3), docs\plans\phase-4-execution.md
- scope: experiment execution
- description: Lock the experiment design before running, then execute implementations (3) × fault types (2) for at least 10 repetitions per combination, recording raw data for every run. Varied condition: implementation × fault type. Fixed: hybrid group config, network, audit/logging settings. Preserve all raw data (never delete prior data; log any mid-run design change with when/what/why).
- acceptance criteria:
  - Raw-data count matches the designed sample size.
  - Procedure is reproducible by a third party.
  - Filenames/metadata encode implementation, fault type, repetition number, and run conditions.

## REQ-observation-metrics

- source: D:\sr\pq-hybrid-downgrade\docs\PROPOSAL.md (§4.4)
- scope: measurement
- description: For every run, record three metrics: (1) negotiated result group — whether the final key_share group is hybrid or classical-only; (2) audit-tool detection — whether standard logging (SSLKEYLOGFILE, -state, -vvv) / Wireshark reveals the downgrade; (3) handshake success/failure — whether manipulated negotiation is rejected or silently succeeds.
- acceptance criteria:
  - All three metrics captured per run as raw data.

## REQ-cross-implementation-analysis

- source: D:\sr\pq-hybrid-downgrade\docs\PROPOSAL.md (§5.4, §6), docs\plans\phase-5-analysis.md
- scope: analysis / conclusion
- description: Organize raw data into per-implementation comparison tables/graphs and judge the hypothesis — is negotiation-logic-driven hybrid-PQ downgrade an accidental single-library bug or a pattern across independent codebases. Separate expected from unexpected results, cite the underlying raw-data values for each judgment, and state limitations.
- acceptance criteria:
  - Results diverging from the hypothesis are included without omission.
  - Conclusions make no claims unsupported by raw data.
  - At least one candidate cause is recorded for each divergent result.

## REQ-reproduction-package

- source: D:\sr\pq-hybrid-downgrade\docs\PROPOSAL.md (§6), docs\plans\phase-6-writeup.md
- scope: deliverables
- description: Produce the paper (intro/method/results/discussion, unified references, ~10-line abstract, cover) plus a single-ZIP reproduction package (raw data + fault-injection scripts + run procedure) and a 3-line AI-vs-own-judgment disclosure.
- acceptance criteria:
  - Deliverable is a single ZIP.
  - Abstract covers problem/method/results.
  - No unfinished markers or placeholders remain.
