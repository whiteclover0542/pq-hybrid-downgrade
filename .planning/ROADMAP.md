# Roadmap: pq-hybrid-downgrade

## Overview

Phase 0(기획)에서 확정된 테스트 가능한 가설을 출발점으로, 문헌으로 근거를 다지고(1) → 3개 독립 구현의 로컬 테스트베드를 세우고(2) → 협상 필드를 조작하는 결함 주입 도구와 관측 하네스를 만들고(3) → 조합당 ≥10회 반복 실행으로 원시 데이터를 수집하고(4) → 교차 구현 비교로 가설을 판정하고(5) → 논문과 단일 ZIP 재현 패키지로 마무리(6)한다. 종착점은 "협상 로직 결함발 하이브리드-PQ 다운그레이드가 일회성 버그인가 교차 구현 패턴인가"에 증거로 답하는 완성된 논문이다.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

> Phase 0 (기획/planning) 완료 — PROPOSAL.md 산출. 로드맵은 Phase 1부터 실행한다.

- [x] **Phase 1: 문헌 조사** - 선행연구 존재 검증 + 기준 사례 CVE-2026-2673 소스 수준 분석
- [ ] **Phase 2: 실험 환경 구축** - 3개 독립 하이브리드-KEM 구현 로컬 빌드 + 정상 핸드셰이크 기준선
- [ ] **Phase 3: 실험 도구 개발** - MITM Fault Injector(2 결함 유형) + 지표 자동 수집 하네스
- [ ] **Phase 4: 실험 실행** - 설계 고정 후 구현(3)×결함유형(2) 조합당 ≥10회 반복 실행
- [ ] **Phase 5: 결과 분석** - 교차 구현 비교로 가설(버그 대 패턴) 판정
- [ ] **Phase 6: 논문 작성·제출** - 논문 + 단일 ZIP 재현 패키지 + AI/본인 판단 공개

## Phase Details

### Phase 1: 문헌 조사
**Goal**: 가설을 뒷받침하는 선행연구의 존재를 검증하고, 기준 사례 CVE-2026-2673을 소스 수준에서 이해하여 "이미 알려진 사실"과 "이 연구의 새 주장"을 분리한다.
**Depends on**: Nothing (Phase 0 기획 완료; 첫 실행 단계)
**Requirements**: REQ-prior-work-verification
**Success Criteria** (what must be TRUE):
  1. 데이터로 검증된 선행연구가 최소 1건 목록에 오르고, 각 인용의 존재 검증 방법이 기록되어 있다.
  2. "이미 알려진 사실"과 "이 연구의 새 주장"이 분리되어 있다.
  3. CVE-2026-2673의 권고문·영향 버전·결함 메커니즘이 분석 노트로 정리되어 있다.
  4. 배경 CVE 3건(FreeRDP, Cisco, NGINX)이 NVD에서 재확인되고, 존재하지 않거나 불일치하는 인용은 사유와 함께 제외되어 있다.
**Plans**: [Phase 1 문헌 조사 계획](phases/01-literature/01-01-PLAN.md)

### Phase 2: 실험 환경 구축
**Goal**: 독립적인 3개 하이브리드-KEM 코드베이스를 로컬에 구축하고, 조작 없는 정상 하이브리드 핸드셰이크 기준선을 확보한다.
**Depends on**: Phase 1
**Requirements**: REQ-testbed-three-implementations
**Success Criteria** (what must be TRUE):
  1. 세 구현(OpenSSL+oqs-provider X25519MLKEM768, BoringSSL X25519Kyber768, OpenSSH sntrup761x25519-sha512) 모두 조작 없는 하이브리드 핸드셰이크를 완료한다.
  2. 각 구현에서 협상된 그룹을 로그로 관찰할 수 있다.
  3. 각 구현의 버전/커밋 해시/빌드 옵션이 재현용으로 기록되어 있다.
  4. 감사·로깅 경로(SSLKEYLOGFILE, s_server -state, sshd -vvv, Wireshark 캡처)가 확인되어 있다.
**Plans**: TBD

### Phase 3: 실험 도구 개발
**Goal**: TLS 레코드 계층을 가로채 협상 필드를 조작하는 MITM Fault Injector와, 관측 지표를 자동 수집하는 결과 하네스를 만든다.
**Depends on**: Phase 2
**Requirements**: REQ-fault-injector, REQ-observation-metrics
**Success Criteria** (what must be TRUE):
  1. 두 결함 유형(그룹 목록 조작, 결합자 바인딩 위반)을 세 구현 각각에 적용할 수 있다.
  2. 조작이 실제로 적용됐는지 확인하는 검증 스크립트가 도구 버그와 진짜 "무결함" 결과를 구분한다.
  3. 매 실행마다 세 관측 지표(협상 결과 그룹, 감사 도구 탐지, 핸드셰이크 성공/실패)가 구조화된 원시 데이터로 자동 기록된다.
**Plans**: TBD

### Phase 4: 실험 실행
**Goal**: 실행 전 실험 설계를 고정하고, 구현(3)×결함유형(2) 조합을 조합당 최소 10회 반복 실행하여 모든 원시 데이터를 보존한다.
**Depends on**: Phase 3
**Requirements**: REQ-repeated-execution
**Success Criteria** (what must be TRUE):
  1. 원시 데이터 개수가 설계된 표본 크기와 일치한다.
  2. 파일명/메타데이터가 구현·결함유형·반복번호·실행조건을 인코딩한다.
  3. 절차가 제3자에 의해 재현 가능하다.
  4. 실행 중 설계 변경은 시점/내용/이유와 함께 기록되며, 기존 원시 데이터는 삭제되지 않는다.
**Plans**: TBD

### Phase 5: 결과 분석
**Goal**: 원시 데이터를 구현별 비교로 정리하고 가설을 판정한다 — 협상 로직발 하이브리드-PQ 다운그레이드가 단일 라이브러리 버그인가 독립 코드베이스 전반의 패턴인가.
**Depends on**: Phase 4
**Requirements**: REQ-cross-implementation-analysis, REQ-hypothesis-lock
**Success Criteria** (what must be TRUE):
  1. 무엇이 무엇에 영향을 주는지 한 문장으로 보이는 테스트 가능한 가설과, 버그-대-패턴으로 좁혀진 연구 질문이 명시되어 있다.
  2. 구현별 비교 표/그래프가 작성되고, 각 판정이 근거한 원시 데이터 값이 인용되어 있다.
  3. 가설과 어긋나는 결과가 누락 없이 포함되고, 각 divergence마다 후보 원인이 최소 1개 기록되어 있다.
  4. 결론은 원시 데이터에 없는 주장을 하지 않으며, 한계가 명시되어 있다.
**Plans**: TBD

### Phase 6: 논문 작성·제출
**Goal**: 논문 + 재현 패키지 + AI/본인 판단 공개를 한 세트로 묶어 제출한다.
**Depends on**: Phase 5
**Requirements**: REQ-reproduction-package
**Success Criteria** (what must be TRUE):
  1. 서론/방법/결과/논의 구성의 완성된 논문과 통합 참고문헌, 문제/방법/결과를 담은 ~10줄 초록, 표지가 존재한다.
  2. 원시 데이터 + 결함 주입 스크립트 + 실행 절차가 단일 ZIP 재현 패키지로 묶여 있고, 다른 위치에서 풀어도 파일 누락이 없다.
  3. 3줄 AI-대-본인 판단 공개가 포함되어 있다.
  4. 미완성 표시나 플레이스홀더가 남아 있지 않다.
**Plans**: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5 → 6

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. 문헌 조사 | 1/1 | Complete | 2026-09-22 |
| 2. 실험 환경 구축 | 0/TBD | Not started | - |
| 3. 실험 도구 개발 | 0/TBD | Not started | - |
| 4. 실험 실행 | 0/TBD | Not started | - |
| 5. 결과 분석 | 0/TBD | Not started | - |
| 6. 논문 작성·제출 | 0/TBD | Not started | - |
