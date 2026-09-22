# Context (from DOCs)

Running notes from the 8 DOC-type sources, keyed by topic with source attribution. These are project-state and per-phase-plan material that elaborate the PROPOSAL (PRD); they define no decisions or contracts.

---

## Topic: Project state & phase roadmap

- source: D:\sr\pq-hybrid-downgrade\docs\PROGRESS.md
- Last updated 2026-09-22. Single-author security-research project.
- 6-phase work order (per-phase detail lives in docs/plans/):
  - Phase 0 — 기획 (topic + proposal): ✅ 완료
  - Phase 1 — 문헌 조사 (prior work + CVE verification): ⬜ 미완료
  - Phase 2 — 실험 환경 구축 (build 3 implementations): ⬜ 미완료
  - Phase 3 — 실험 도구 개발 (fault injector): ⬜ 미완료
  - Phase 4 — 실험 실행 (repeated measurement, raw-data collection): ⬜ 미완료
  - Phase 5 — 결과 분석 (interpretation, hypothesis judgment): ⬜ 미완료
  - Phase 6 — 논문 작성·제출 (paper + reproduction package): ⬜ 미완료
- Master to-do list mirrors the phases (literature list, CVE-2026-2673 analysis, three builds, injector+harness, repeated runs, comparison tables, limitations/conclusion, ZIP package + final verification).
- Completed log: 2026-09-22 topic finalized; 2026-09-22 PROPOSAL.md authored.

## Topic: Phase 0 — 기획 (planning)

- source: D:\sr\pq-hybrid-downgrade\docs\plans\phase-0-planning.md
- Status: ✅ 완료 (2026-09-22). Goal: finalize topic and produce a proposal with a testable hypothesis and experiment design.
- Deliverable: PROPOSAL.md.
- Done criteria: hypothesis stated as one "what-affects-what" sentence; what is changed vs. observed is defined.

## Topic: Phase 1 — 문헌 조사 (literature review)

- source: D:\sr\pq-hybrid-downgrade\docs\plans\phase-1-literature.md
- Goal: verify existence of supporting prior work and understand baseline case CVE-2026-2673 at source level; separate "already known" from "newly claimed".
- Tasks: list prior work (Bhargavan et al. downgrade-resistance definition; "Transcript-Bound Combiners for Downgrade-Resilient Hybrid PQ Key Establishment" 2026-09); verify each work's existence (title search, author/year, abstract); one-line link of each work to the hypothesis; exclude nonexistent/mismatched works with reason; CVE-2026-2673 deep analysis (OpenSSL advisory, affected versions, flaw mechanism); re-check 3 background CVEs (FreeRDP, Cisco, NGINX) on NVD.
- Deliverables: reference list (author/year/source + hypothesis link + verification method), excluded-works list with reasons, CVE-2026-2673 analysis notes.
- Caution: AI-suggested references may be hallucinated — verify each in person; numbers/conclusions checked against source (only summary/translation delegated to AI).

## Topic: Phase 2 — 실험 환경 구축 (testbed)

- source: D:\sr\pq-hybrid-downgrade\docs\plans\phase-2-testbed.md
- Goal: build 3 independent hybrid-KEM codebases locally and secure a normal-handshake baseline.
- Targets: OpenSSL + oqs-provider (X25519MLKEM768, CVE-2026-2673 target line); BoringSSL (X25519Kyber768); OpenSSH (sntrup761x25519-sha512).
- Record each implementation's version/commit hash/build options; confirm audit/logging paths (SSLKEYLOGFILE, s_server -state, sshd -vvv, Wireshark).
- Done criteria: all 3 complete an unmanipulated hybrid handshake; negotiated group observable in logs.
- Caution: pin versions exactly — the flaw may exist only in specific versions; essential for reproduction.

## Topic: Phase 3 — 실험 도구 개발 (tooling / fault injector)

- source: D:\sr\pq-hybrid-downgrade\docs\plans\phase-3-tooling.md
- Goal: build a MITM Fault Injector that manipulates negotiation fields, plus an auto-collecting results harness.
- Injector skeleton: intercept TLS record layer between client/server (Python scapy or s_client/s_server low-level hooking; optionally mitmproxy-style extension).
- Fault type 1 — group-list manipulation: remove / reorder hybrid groups in supported_groups/KEX list.
- Fault type 2 — combiner-binding violation: keep only one of two components (classical/PQ) real, forge the rest.
- Harness records negotiated group, audit-tool detection, handshake success/failure as structured raw data.
- Short verification script confirms manipulation actually applied (separates tool bugs from real results).
- Done criteria: both fault types applicable to all 3 implementations; 3 metrics auto-recorded per run.
- Caution: verify manipulation took effect first — a silently-failing tool can be misread as "no flaw".

## Topic: Phase 4 — 실험 실행 (execution)

- source: D:\sr\pq-hybrid-downgrade\docs\plans\phase-4-execution.md
- Goal: fix the design, then run to completion and preserve raw data; lock conditions and repetition count before running so results aren't cherry-picked.
- Design (fixed before run): varied = implementation (3) × fault type (group-list manipulation / combiner-binding violation); fixed = hybrid group config, network, audit/logging; repetitions = ≥10 per combination; measured = ① negotiated group (hybrid/classical) ② audit-tool detection ③ handshake success/failure.
- Tasks: one trial run to check for missing recorded values; run all combinations ≥10×; save per-run logs/packet captures with run conditions in filename/metadata; log any mid-run design change (when/what/why) without deleting prior data.
- Done criteria: raw-data count matches designed sample size; procedure reproducible by others.
- Caution: if results vary per run, record the variance itself — it's a finding; keep hypothesis-rejecting results as-is, don't edit to fit.

## Topic: Phase 5 — 결과 분석 (analysis)

- source: D:\sr\pq-hybrid-downgrade\docs\plans\phase-5-analysis.md
- Goal: organize raw data and judge the hypothesis. Core question: is negotiation-logic-driven hybrid-PQ downgrade an accidental single-library bug or a cross-implementation pattern.
- Tasks: per-implementation comparison tables/graphs; separate expected vs. divergent results; cite which raw-data value grounds each judgment; review candidate causes for divergences (data-verifiable first); if needed re-run with changed conditions or revise hypothesis (record before/after); write conclusion (≥1 paragraph) and limitations.
- Done criteria: all hypothesis-divergent results included; conclusion claims nothing absent from raw data; ≥1 candidate cause recorded per divergence.
- Caution: make judgments yourself — delegate only summarization to AI, never the conclusion.

## Topic: Phase 6 — 논문 작성·제출 (writeup / submission)

- source: D:\sr\pq-hybrid-downgrade\docs\plans\phase-6-writeup.md
- Goal: bundle one showable set — paper + reproduction package + 3-line AI/own-judgment disclosure.
- Tasks: body in intro/method/results/discussion order; references after body with unified formatting; cross-check in-text citations against list; abstract last (~10 lines, covering problem/method/results); cover (title/author/date); reproduction instructions (what data from where, what to run); organize raw data + run scripts into a folder; 3-line AI-vs-own-judgment split; bundle all into one ZIP and unpack elsewhere to check for missing files; final sweep for unfinished markers/placeholders; if a submission URL exists, confirm it opens in an incognito window without login/auth.
- Deliverables: one finished paper; reproduction-package ZIP (raw data + scripts + procedure); 3-line AI/own-judgment note.
- Done criteria: submission is a single ZIP; abstract covers problem/method/results; no unfinished markers or placeholders.
- Caution: length is not the bar — if hypothesis/evidence/data/conclusion connect, a short paper is still a paper.

## Topic: Motivating CVE observations (background)

- source: D:\sr\pq-hybrid-downgrade\docs\PROPOSAL.md (§2)
- Origin: author runs Today-CVE-information (github.com/whiteclover0542/Today-CVE-information, since 2026-08-22), auto-collecting new NVD CVEs. Records 2026-08-23~09-22 showed a recurring pattern of negotiation/handshake logic flaws.
- Three background CVEs, common thread = flaw location (negotiation/handshake stage) not flaw type, all appearing outwardly normal:
  - CVE-2026-91949 (2026-09-16) — FreeRDP server protocol-negotiation bypass.
  - CVE-2026-20249 (2026-09-17) — Cisco ASA/FTD IKEv2 authentication-stage logic error.
  - CVE-2026-90439 (2026-09-16) — NGINX + OpenSSL ≤3.5.0, HTTP/3 TLS handshake heap buffer overflow.
- Baseline case: CVE-2026-2673 (disclosed 2026-03-13) — same OpenSSL 3.5 line; PQ hybrid group negotiation silently downgrades to classical in a way standard TLS audit tools miss. This narrowed the topic to the bug-vs-pattern question.
