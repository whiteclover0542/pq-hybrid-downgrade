# pq-hybrid-downgrade 진행 현황

- 마지막 업데이트: 2026-09-23
- 기획: [PROPOSAL.md](PROPOSAL.md) · 로드맵: [.planning/ROADMAP.md](../.planning/ROADMAP.md) · 상태: [.planning/STATE.md](../.planning/STATE.md)
- **현재 Phase:** Phase 4 — 실험 실행

## 완료 현황

| 상태 | Phase | 산출물 |
|---|---|---|
| 완료 | 1. 문헌 조사 | [phase-1-synthesis.md](research/phase-1-synthesis.md) |
| 완료 | 2. 실험 환경 구축 | [환경 대장](research/phase-2-environment.md), [baseline](research/baselines/), [검증 보고서](../.planning/phases/02-testbed/02-VERIFICATION.md) |
| 완료 | 3. 실험 도구 개발 | [설계](research/phase-3-experiment-design.md), [도구](../tools/faultinject/), [완료 요약](../.planning/phases/03-tooling/03-01-SUMMARY.md) |
| 예정 | 4. 실험 실행 | Phase 3 이후 |
| 예정 | 5. 결과 분석 | Phase 4 이후 |
| 예정 | 6. 논문 작성·제출 | Phase 5 이후 |

## 다음 작업

- [ ] Phase 4 계획 작성: 3개 구현 × 2개 결함 경로를 조합당 최소 10회 반복 실행할 절차와 보존 규칙을 확정합니다.

## Phase 2 완료 기록

| 커밋 | 내용 |
|---|---|
| `daadf13` | OpenSSL + oqs-provider hybrid baseline |
| `ac88fca` | BoringSSL hybrid baseline |
| `ed2e008` | OpenSSH hybrid KEX baseline |
| `bbf4c99` | 재현 환경 대장 |
| `b9b8528` | Phase 2 plan summary·추적 갱신 |
| `a747221` | Phase 2 검증 통과·상태 갱신 |
| `71d8c5d` | progress report 생성(이후 본 루트 파일로 정정) |
| `128b11a` | PROJECT.md의 Phase 2 context 갱신 |

## Phase 3 완료 기록

- [확실] `python -m faultinject.run --smoke`는 3개 구현 × 2개 결함 경로를 1회씩 실행하고 각 JSON의 `manipulation_verified`를 갱신합니다.
- [확실] `group-list` 3개 실행은 고전 그룹/KEX 협상과 연결 성공을 기록했습니다.
- [확실] `binding` 3개 실행은 프록시 조작 적용을 검증했고, 연결 실패 기록과 분리해 보존했습니다.
- [확실] 원시 로그·pcap·프록시 로그·JSON은 `docs/research/baselines/raw/phase-3/`에 보존됩니다.

## Phase 4 인계 조건

- [확실] 각 구현체의 실제 협상 group/KEX는 Phase 2 client log를 기준으로 판정합니다.
- [확실] packet capture는 보조 증적이며, 조작 적용 여부는 별도 검증 스크립트로 확인해야 합니다.
