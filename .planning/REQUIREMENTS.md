# Requirements: pq-hybrid-downgrade

**Defined:** 2026-09-22
**Core Value:** 증거로 뒷받침된 결론(협상 로직 결함발 하이브리드-PQ 다운그레이드가 일회성 버그인가 교차 구현 패턴인가)에 답하는 완성된 논문과 재현 패키지

> ID 규약: 원본 인텔의 `REQ-*` 슬러그 ID를 그대로 보존한다(인텔 파일 전반에서 이 ID로 추적됨).

## v1 Requirements

Requirements for the initial research deliverable. Each maps to exactly one roadmap phase.

### Research Framing (연구 프레이밍)

- [ ] **REQ-hypothesis-lock**: 무엇이 무엇에 영향을 주는지 한 문장으로 보이는 테스트 가능한 가설을 고정하고, "증명된-안전 설계"와 "배포된-안전"을 구분하며, 연구 질문을 독립 코드베이스 전반의 버그-대-패턴으로 좁힌다.

### Literature (문헌)

- [x] **REQ-prior-work-verification**: 다운그레이드-저항 하이브리드 PQ 콤바이너 선행연구(Bhargavan et al. 정의; "Transcript-Bound Combiners..." 2026-09) 존재를 검증하고, 기준 사례 CVE-2026-2673을 소스 수준(권고문·영향 버전·결함 메커니즘)에서 분석하며, 배경 CVE 3건(FreeRDP CVE-2026-91949, Cisco CVE-2026-20249, NGINX+OpenSSL CVE-2026-90439)을 NVD에서 재확인한다. 존재 검증 실패/불일치 인용은 사유와 함께 제외한다.

### Testbed (실험 환경)

- [ ] **REQ-testbed-three-implementations**: 3개 독립 하이브리드-KEM 코드베이스를 로컬에 빌드하고 각각의 조작 없는 정상 하이브리드 핸드셰이크 기준선을 확보한다 — OpenSSL+oqs-provider(X25519MLKEM768; CVE-2026-2673 대상 계열), BoringSSL(X25519Kyber768), OpenSSH(sntrup761x25519-sha512). 버전/커밋 해시/빌드 옵션과 감사·로깅 경로를 기록한다.

### Tooling (실험 도구)

- [ ] **REQ-fault-injector**: TLS 레코드 계층을 가로채 협상 필드를 조작하는 MITM Fault Injector와 결과 수집 하네스를 만든다. 결함 2유형 — (1) 그룹 목록 조작(하이브리드 그룹 제거/재정렬로 classical-only 폴백 유도), (2) 결합자 바인딩 위반(두 성분 중 하나만 실제값, 나머지 위조하여 transcript-binding 검증 여부 시험). 조작 실제 적용을 확인하는 검증 스크립트 포함.
- [ ] **REQ-observation-metrics**: 매 실행마다 3개 지표를 원시 데이터로 기록한다 — (1) 협상 결과 그룹(최종 key_share가 하이브리드/classical-only), (2) 감사 도구 탐지 여부(SSLKEYLOGFILE, -state, -vvv, Wireshark), (3) 핸드셰이크 성공/실패(조작 협상이 거부되는가 조용히 성공하는가).

### Execution (실험 실행)

- [ ] **REQ-repeated-execution**: 실행 전 설계를 고정한 뒤 구현(3)×결함유형(2)을 조합당 최소 10회 실행하고 매 실행 원시 데이터를 기록한다. 변인 = 구현×결함유형; 고정 = 하이브리드 그룹 설정·네트워크·감사/로깅. 모든 원시 데이터 보존, 실행 중 설계 변경은 시점/내용/이유 기록. 파일명/메타데이터에 구현·결함유형·반복번호·실행조건 인코딩.

### Analysis (결과 분석)

- [ ] **REQ-cross-implementation-analysis**: 원시 데이터를 구현별 비교 표/그래프로 정리하고 가설을 판정한다 — 협상 로직발 하이브리드-PQ 다운그레이드가 단일 라이브러리 버그인가 독립 코드베이스 전반의 패턴인가. 기대/비기대 결과를 분리하고, 각 판정의 근거 원시 데이터 값을 인용하며, 각 divergence마다 후보 원인을 최소 1개 기록하고 한계를 명시한다.

### Deliverables (산출물)

- [ ] **REQ-reproduction-package**: 논문(서론/방법/결과/논의, 통합 참고문헌, ~10줄 초록, 표지)과 단일 ZIP 재현 패키지(원시 데이터 + 결함 주입 스크립트 + 실행 절차), 3줄 AI-대-본인 판단 공개를 산출한다. 미완성 표시/플레이스홀더 없음.

## v2 Requirements

Deferred to future work. Tracked but not in current roadmap.

### Coverage Expansion

- **EXPN-01**: 세 구현을 넘어선 추가 하이브리드-KEM 라이브러리로 실험 확장.
- **EXPN-02**: 원격/실배포 환경 관측(로컬 통제 실험 이후).

## Out of Scope

Explicitly excluded. Documented to prevent scope creep.

| Feature | Reason |
|---------|--------|
| 신규 다운그레이드-저항 콤바이너 설계·증명 | 이 연구는 배포 구현의 as-deployed 안전성 경험 시험에 한정 |
| 원격/클라우드 대규모 스캔 | 로컬 연구 환경 범위; 통제된 로컬 실험이 버그-대-패턴 질문에 충분 |
| 3개 초과 구현 커버리지 | v1은 OpenSSL+oqs / BoringSSL / OpenSSH로 고정; 확장은 v2 |

## Traceability

Which phases cover which requirements. Each requirement maps to exactly one phase.

| Requirement | Phase | Status |
|-------------|-------|--------|
| REQ-prior-work-verification | Phase 1 | Complete |
| REQ-testbed-three-implementations | Phase 2 | Pending |
| REQ-fault-injector | Phase 3 | Pending |
| REQ-observation-metrics | Phase 3 | Pending |
| REQ-repeated-execution | Phase 4 | Pending |
| REQ-cross-implementation-analysis | Phase 5 | Pending |
| REQ-hypothesis-lock | Phase 5 | Pending |
| REQ-reproduction-package | Phase 6 | Pending |

**Coverage:**
- v1 requirements: 8 total
- Mapped to phases: 8
- Unmapped: 0 ✓

---
*Requirements defined: 2026-09-22 (from ingest of docs/PROPOSAL.md)*
*Last updated: 2026-09-22 after initial roadmap creation*
