---
gsd_state_version: 1.0
milestone: v1.1
milestone_name: HRR-absence hybrid-downgrade study
status: complete
stopped_at: v1.1-P4 complete; validated publication and reproduction package pushed to origin/v1.1-hrr-downgrade
last_updated: 2026-09-28T00:00:00Z
last_activity: 2026-09-28
progress:
  total_phases: 4
  completed_phases: 4
  total_plans: 4
  completed_plans: 4
  percent: 100
---

# v1.1 P2 Historical Execution Record (2026-09-25)

[확실] P2 repeated execution is complete. A clean `raw/v1.1/` run produced 90 JSON records: every one of the nine implementation/condition combinations has exactly one record for each repetition r01 through r10. The run ended with status 0 and an empty stderr log.

[확실] All 90 PCAPs, client logs, and capture logs exist and are non-empty; all 30 on-path runs also have non-empty proxy logs. Every record has `manipulation_verified=True`.

[확실] 이 기록은 당시의 P2 인계입니다. 이후 P3 분석과 P4 논문·재현 패키지 갱신이 완료됐으며, P2 자체는 관측값만 기록하고 새로운 취약점 결론을 추가하지 않았습니다.

See: `.planning/phases/07-v11-tooling/07-02-SUMMARY.md`.

# v1.1 P3 Historical Analysis Record (2026-09-25)

[확실] P3 analyzed only the final 90-record `raw/v1.1/` dataset. It confirms the scoped observation that both tested TLS implementations completed the configured classical negotiation after hybrid advertisement, with no recorded HRR or automatic downgrade flag.

[불확실] The P3 result does not establish RFC non-conformance, practical exploitability, or a new vulnerability. The full evidence table, limits, and OpenSSH control interpretation are in `docs/research/v1.1-p3-analysis.md`.

[확실] 이 기록은 당시의 P3 인계입니다. 이후 P4가 완료되어 논문과 재현 패키지가 갱신·검증됐습니다.

# v1.1 P4 Publication Record (2026-09-28)

[확실] P4 published the v1.1-only paper, safe reproduction guide, and rebuilt `dist/pq-hybrid-downgrade-v11-repro.zip`. The final verification found 90 JSON records across nine complete r01–r10 groups, 90 verified manipulations, all required artifacts, and a valid ZIP with no diagnostic or preflight paths.

[확실] The P4 test suite completed with `69 passed, 1 skipped`; the skip is the environment-dependent tshark case. The sole warning concerned pytest cache-file permissions.

[불확실] The published conclusion remains restricted to the tested implementations, group order, loopback environment, and audit definition. It does not establish RFC non-conformance, CVE equivalence, practical exploitability, or a new vulnerability.

See: `.planning/phases/07-v11-tooling/07-04-SUMMARY.md`.

# Project State

## Current Position — v1.1

Phase: v1.1 P4 of P4 완료
Plan: `07-04-SUMMARY.md` 완료
Status: 논문·재현 안내·재현 ZIP 검증 및 원격 푸시 완료
Last activity: 2026-09-28 — 최종 데이터 검증, P4 문서 갱신, 재현 ZIP 검증, `origin/v1.1-hrr-downgrade` 푸시 완료

Progress: [■■■■] 100% (P1 도구 확장, P2 반복 실행, P3 분석, P4 논문·재현 패키지 갱신 완료)

### Completed Deliverables

- [확실] P2: 9개 구현×조건 조합을 r01–r10으로 실행해 최종 JSON 90건과 필수 artifact를 보존했습니다.
- [확실] P3: 조건 축·HRR·감사 가시성을 분석하고 관측 범위를 문서화했습니다.
- [확실] P4: v1.1 전용 논문·안전한 재현 안내·검증된 재현 ZIP을 갱신해 원격 브랜치에 푸시했습니다.

### Scope Boundary

- [불확실] v1.1 결과는 고정된 구현·그룹 순서·loopback 환경·감사 정의의 관측입니다. RFC 위반, CVE 동일성, 실환경 공격 가능성 또는 새 취약점을 판정하지 않습니다.

## v1.0 Historical State

## Project Reference

See: .planning/PROJECT.md (updated 2026-09-22)

**Core value:** 증거로 뒷받침된 결론으로 하이브리드 PQ 다운그레이드가 단일 버그인지 교차 구현 패턴인지 판정하는 것입니다.
**Current focus:** 밀스톤 v1.0 완료 — 다음 밀스톤 없음(후속 확장은 REQUIREMENTS.md v2 참고)

## Current Position

Phase: 6 of 6 (논문 작성·제출) — 완료
Plan: 06-01-PLAN.md 완료
Status: 밀스톤 완료
Last activity: 2026-09-23 — Phase 6 논문 완성·단일 ZIP 재현 패키지 검증·AI-대-본인 판단 공개 작성 완료

Progress: [██████████] 100% (Phase 1 문헌 조사, Phase 2 실험 환경 구축, Phase 3 실험 도구 개발, Phase 4 실험 실행, Phase 5 결과 분석, Phase 6 논문 작성·제출 완료)

## Performance Metrics

**Velocity:**

- Total plans completed: 6
- Latest completed plan: Phase 6 Plan 01 (paper finalization + repro package + AI-vs-human disclosure)

**By Phase:**

| Phase | Plans | Status |
|---|---:|---|
| 1. 문헌 조사 | 1/1 | Complete |
| 2. 실험 환경 구축 | 1/1 | Complete |
| 3. 실험 도구 개발 | 1/1 | Complete |
| 4. 실험 실행 | 1/1 | Complete |
| 5. 결과 분석 | 1/1 | Complete |
| 6. 논문 작성·제출 | 1/1 | Complete |

## Accumulated Context

### Decisions

- [확실] 대상 구현체는 OpenSSL+oqs-provider, BoringSSL, OpenSSH 세 개로 고정합니다.
- [확실] Phase 2 baseline은 custom binary 절대 경로, 명시적 동적 라이브러리 경로, loopback pcap을 사용합니다.
- [확실] BoringSSL의 관측 이름은 `X25519Kyber768Draft00`이며, 계획의 `X25519Kyber768` 표기 및 TLS code point `0x6399`와 함께 보존합니다.

### Pending Todos

- [확실] 없음 — v1.0 밀스톤의 모든 phase(1~6)가 완료되었습니다. 후속 확장은 REQUIREMENTS.md v2(EXPN-01, EXPN-02)에 이연되어 있으며 현재 활성 계획은 없습니다.

### Blockers/Concerns

- [확실] 없음 — Phase 6 완료 기준 4개(완성된 논문, 단일 ZIP 재현 패키지, 3줄 AI-대-본인 판단 공개, 플레이스홀더 없음) 모두 충족했습니다.

## Session Continuity

Last session: 2026-09-23
Stopped at: Phase 6(논문 작성·제출) 완료 — 논문 완성, 단일 ZIP 재현 패키지 검증(`verify_zip` → `(True, [])`), AI-대-본인 판단 공개 작성, 전체 테스트 42 passed/1 skipped. v1.0 밀스톤 완료.
Resume file: .planning/phases/06-paper/06-01-SUMMARY.md
