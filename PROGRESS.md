# pq-hybrid-downgrade 진행 현황

- 마지막 업데이트: 2026-09-22
- 기획: [PROPOSAL.md](docs/PROPOSAL.md) · 로드맵: [.planning/ROADMAP.md](.planning/ROADMAP.md) · 상태: [.planning/STATE.md](.planning/STATE.md)
- **현재 Phase:** Phase 3 — 실험 도구 개발

## 완료 현황

| 상태 | Phase | 산출물 |
|---|---|---|
| 완료 | 1. 문헌 조사 | [phase-1-synthesis.md](docs/research/phase-1-synthesis.md) |
| 완료 | 2. 실험 환경 구축 | [환경 대장](docs/research/phase-2-environment.md), [baseline](docs/research/baselines/), [검증 보고서](.planning/phases/02-testbed/02-VERIFICATION.md) |
| 예정 | 3. 실험 도구 개발 | Phase 3 plan 작성 필요 |
| 예정 | 4. 실험 실행 | Phase 3 이후 |
| 예정 | 5. 결과 분석 | Phase 4 이후 |
| 예정 | 6. 논문 작성·제출 | Phase 5 이후 |

## 다음 작업

- [ ] Phase 3 계획 작성: MITM Fault Injector와 관측 수집 하네스의 구현·검증 기준을 확정합니다.

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

## Phase 3 인계 조건

- [확실] 각 구현체의 실제 협상 group/KEX는 Phase 2 client log를 기준으로 판정합니다.
- [확실] packet capture는 보조 증적이며, 조작 적용 여부는 별도 검증 스크립트로 확인해야 합니다.
