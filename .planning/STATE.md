---
gsd_state_version: 1.0
milestone: v1.1
milestone_name: HRR-absence hybrid-downgrade study
status: in_progress
stopped_at: v1.1-P3 complete; P4 paper/reproduction update is pending
last_updated: 2026-09-25T00:00:00Z
last_activity: 2026-09-25
progress:
  total_phases: 4
  completed_phases: 3
  total_plans: 4
  completed_plans: 3
  percent: 75
---

# v1.1 P2 Execution Record (2026-09-25)

[확실] P2 repeated execution is complete. A clean `raw/v1.1/` run produced 90 JSON records: every one of the nine implementation/condition combinations has exactly one record for each repetition r01 through r10. The run ended with status 0 and an empty stderr log.

[확실] All 90 PCAPs, client logs, and capture logs exist and are non-empty; all 30 on-path runs also have non-empty proxy logs. Every record has `manipulation_verified=True`.

[확실] P3 is now the next phase. P2 only records observations; it makes no new vulnerability conclusion and does not update the paper.

See: `.planning/phases/07-v11-tooling/07-02-SUMMARY.md`.

# v1.1 P3 Analysis Record (2026-09-25)

[확실] P3 analyzed only the final 90-record `raw/v1.1/` dataset. It confirms the scoped observation that both tested TLS implementations completed the configured classical negotiation after hybrid advertisement, with no recorded HRR or automatic downgrade flag.

[불확실] The P3 result does not establish RFC non-conformance, practical exploitability, or a new vulnerability. The full evidence table, limits, and OpenSSH control interpretation are in `docs/research/v1.1-p3-analysis.md`.

[확실] P4 is now next. The paper and reproduction package remain unchanged until P4.

# Project State

## Current Position — v1.1

Phase: v1.1 P1 of P4 (도구 확장) 완료
Plan: `07-01-PLAN.md` 완료
Status: P2 반복 실행 대기
Last activity: 2026-09-25 — `verify_condition()` 구현과 WSL TShark 필드 파서 직접 확인 후 P1 인계 문서를 작성함

Progress: [■□□□] 25% (P1 도구 확장 완료, P2 반복 실행·P3 분석·P4 논문 갱신 대기)

### Pending Todos

- [확실] P2: WSL에서 9개 v1.1 조건을 조합당 10회 이상 실행하고 원시 산출물을 보존합니다.
- [확실] P3: 조건 축·HRR·감사 가시성 지표로 P2 결과를 분석합니다.
- [확실] P4: 검증된 P2/P3 결과만 사용해 논문과 재현 패키지를 갱신합니다.

### Blockers/Concerns

- [확실] P2를 실행하려면 WSL의 `/root/pq-hybrid-phase2` 바이너리, OQS provider, TShark가 모두 필요합니다.
- [확실] Windows에서는 TShark 의존 테스트 1건이 skip되므로, P2 시작 전 WSL에서의 프리플라이트가 필요합니다.

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
