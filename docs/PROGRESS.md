# pq-hybrid-downgrade 진행 현황

- 마지막 업데이트: 2026-09-22
- 기획서: [PROPOSAL.md](docs/PROPOSAL.md) · 로드맵: [ROADMAP.md](.planning/ROADMAP.md) · 상태: [STATE.md](.planning/STATE.md)
- **현재 Phase: [Phase 3 — 실험 도구 개발](#phase-3--실험-도구-개발-)**

범례: ✅ 완료 · 🔄 진행 중 · ⬜ 미완료

진행 규칙: 맨 위 표로 전체 순서를 보고, 세부 작업·메모·완료 기록은 아래 Phase별 섹션에 적는다. Phase를 시작하면 plan(`.planning/phases/NN-<이름>/NN-01-PLAN.md`)을 먼저 쓰고, 위의 "현재 Phase" 링크를 옮긴다.

---

## 1. 전체 순서

| 상태 | Phase | 목표 | 산출물 |
|---|---|---|---|
| ✅ | 0. 기획 | 테스트 가능한 가설 확정 | `docs/PROPOSAL.md` |
| ✅ | 1. 문헌 조사 | 선행연구 검증 + CVE-2026-2673 소스 분석 | `docs/research/phase-1-*` |
| ✅ | 2. 실험 환경 구축 | 3개 구현 빌드 + 정상 핸드셰이크 기준선 | `docs/research/baselines/` |
| ⬜ | 3. 실험 도구 개발 | MITM Fault Injector(2 결함 유형) + 지표 수집 하네스 | — |
| ⬜ | 4. 실험 실행 | 구현(3)×결함(2) 조합당 ≥10회 실행 | — |
| ⬜ | 5. 결과 분석 | 교차 구현 비교로 버그-대-패턴 판정 | — |
| ⬜ | 6. 논문 작성·제출 | 논문 + 단일 ZIP 재현 패키지 | — |

## 2. 지금 할 일

- [ ] Phase 3 plan 작성 → `.planning/phases/03-*/03-01-PLAN.md`

---

## 3. Phase별 상세

### Phase 1 — 문헌 조사 ✅

- 목표: 선행연구 존재 검증 + 기준 사례 CVE-2026-2673 소스 수준 분석
- 요구사항: REQ-prior-work-verification
- plan: [01-01-PLAN.md](.planning/phases/01-literature/01-01-PLAN.md)

| 상태 | Task | 결과물 |
|---|---|---|
| ✅ | 1. 증거 추적 구조 | `docs/research/phase-1-source-ledger.md` |
| ✅ | 2. 하이브리드 컴바이너 선행연구 검증 | ledger |
| ✅ | 3. CVE-2026-2673 소스 수준 분석 | `docs/research/cve-2026-2673.md` |
| ✅ | 4. 배경 CVE 3건 재확인 | `docs/research/background-cves.md` |
| ✅ | 5. 종합 + 사람 최종 확인 게이트 | `docs/research/phase-1-synthesis.md` |

메모:

- 배경 CVE 3건은 NVD `Received` 상태 — 원문 설명과 NVD 처리 상태를 분리해 인용

### Phase 2 — 실험 환경 구축 ✅

- 목표: 3개 독립 하이브리드-KEM 구현 로컬 빌드 + 정상 핸드셰이크 기준선
- 요구사항: REQ-testbed-three-implementations
- plan: [02-01-PLAN.md](.planning/phases/02-testbed/02-01-PLAN.md) · [SUMMARY](.planning/phases/02-testbed/02-01-SUMMARY.md) · [VERIFICATION](.planning/phases/02-testbed/02-VERIFICATION.md)

| 상태 | Task | 결과물 |
|---|---|---|
| ✅ | 1. 빌드 환경 확정·버전 고정 | `docs/research/phase-2-environment.md` |
| ✅ | 2. OpenSSL 3.5.5 + oqs-provider (X25519MLKEM768) | `docs/research/baselines/openssl-baseline.md` |
| ✅ | 3. BoringSSL (X25519Kyber768Draft00, 0x6399) | `docs/research/baselines/boringssl-baseline.md` |
| ✅ | 4. OpenSSH (sntrup761x25519-sha512) | `docs/research/baselines/openssh-baseline.md` |
| ✅ | 5. 감사·로깅 경로 + 원자료 정리 | `docs/research/baselines/raw/` |
| ✅ | 6. 완료 판정 + Phase 3 인계 | VERIFICATION (passed) |

메모 (Phase 3 인계):

- 실행 전 custom binary 절대 경로, `LD_LIBRARY_PATH`, `OPENSSL_MODULES`, OpenSSH KEX 강제 옵션 재검증
- group/KEX 판정은 client log 기준, pcap은 보조 증적

### Phase 3 — 실험 도구 개발 ⬜

- 목표: TLS 레코드 계층 MITM Fault Injector + 관측 지표 자동 수집 하네스
- 요구사항: REQ-fault-injector, REQ-observation-metrics
- plan: 미작성

| 상태 | 작업 |
|---|---|
| ⬜ | plan 작성 |
| ⬜ | 결함 유형 1: 그룹 목록 조작 |
| ⬜ | 결함 유형 2: 결합자 바인딩 위반 |
| ⬜ | 세 구현 각각에 적용 확인 |
| ⬜ | 조작 적용 검증 스크립트 (도구 버그 vs 진짜 무결함 구분) |
| ⬜ | 지표 3종 자동 기록 (협상 그룹 / 감사 도구 탐지 / 핸드셰이크 성패) |

메모:

- 조용한 실패를 "무결함"으로 오독하지 않도록 검증 스크립트 필수

### Phase 4 — 실험 실행 ⬜

- 목표: 실험 설계 고정 후 구현(3)×결함(2) 조합당 ≥10회 반복 실행, 원시 데이터 전량 보존
- 요구사항: REQ-repeated-execution
- plan: 미작성

| 상태 | 작업 |
|---|---|
| ⬜ | plan 작성 |
| ⬜ | 실험 설계 고정 (표본 크기 포함) |
| ⬜ | 파일명/메타데이터 규칙 (구현·결함·반복번호·조건) |
| ⬜ | 6조합 × ≥10회 실행 |
| ⬜ | 원시 데이터 개수 = 설계 표본 크기 확인 |
| ⬜ | 제3자 재현 절차 문서 |
| ⬜ | 설계 변경 로그 (시점/내용/이유, 기존 데이터 삭제 금지) |

### Phase 5 — 결과 분석 ⬜

- 목표: 구현별 비교로 가설(버그 vs 패턴) 판정
- 요구사항: REQ-cross-implementation-analysis, REQ-hypothesis-lock
- plan: 미작성

| 상태 | 작업 |
|---|---|
| ⬜ | plan 작성 |
| ⬜ | 가설·연구 질문 한 문장 고정 |
| ⬜ | 구현별 비교 표/그래프 (원시 데이터 값 인용) |
| ⬜ | 가설과 어긋나는 결과 + divergence별 후보 원인 |
| ⬜ | 결론·한계 정리 (원시 데이터 밖 주장 금지) |

### Phase 6 — 논문 작성·제출 ⬜

- 목표: 논문 + 재현 패키지 + AI/본인 판단 공개를 한 세트로 제출
- 요구사항: REQ-reproduction-package
- plan: 미작성

| 상태 | 작업 |
|---|---|
| ⬜ | plan 작성 |
| ⬜ | 논문 본문 (서론/방법/결과/논의) + 참고문헌 |
| ⬜ | ~10줄 초록 + 표지 |
| ⬜ | 단일 ZIP 재현 패키지 (원시 데이터 + 스크립트 + 절차) |
| ⬜ | 다른 위치에서 압축 해제 후 누락 점검 |
| ⬜ | 3줄 AI-대-본인 판단 공개 |
| ⬜ | 플레이스홀더/미완성 표시 제거 점검 |

---

## 4. 완료한 일

| 날짜 | Phase | 내용 | 관련 |
|---|---|---|---|
| 2026-09-22 | 0 | 문서 정리를 `.planning/`으로 통합 | `445d2a3` |
| 2026-09-22 | 1 | 문헌 조사 완료, plan 이동 | `1c6dcd5` |
| 2026-09-22 | 1 | CVE-2026-90439 설명 정정 | `665ae61`, `429bc83` |
| 2026-09-22 | 1 | 사람 확인 게이트 통과 (6개 출처 직접 열람) | `fbaf0c2` |
| 2026-09-22 | 2 | Phase 2 plan 작성 | `69ed366` |
| 2026-09-22 | 2 | OpenSSL / BoringSSL / OpenSSH baseline | `daadf13`, `ac88fca`, `ed2e008` |
| 2026-09-22 | 2 | 환경 대장 기록, plan 완료 | `bbf4c99`, `b9b8528` |
