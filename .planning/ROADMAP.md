# Roadmap: pq-hybrid-downgrade

## v1.2 final status (2026-09-28)

- [x] **A-0: 사전 확인** — OpenSSL 3.5.5 native-only 재사용 PASS, 3.5.6 수정 대조군 빌드 PASS(`fix-ancestor=yes`, tag `openssl-3.5.6` commit `286ddeaac0...`), BoringSSL 설정 수단 없음 확인(핵심 표본 제외).
- [x] **A-1: 필수 실험 행렬** — 고정 OpenSSL 3.5.5 native-only 클라이언트로 S1(`X25519MLKEM768:X25519`)/S2(`X25519MLKEM768/X25519`)/S3(`DEFAULT`) × 3.5.5/3.5.6 × 10회 = 60회 실행, PCAP HRR 주 판정 및 감사 가시성 실측.
- [x] **B: 판정** — `python -m faultinject.analyze --v12`(tools/에서 실행) → `CVE-2026-2673 verdict: reproduced`(설계 §2.2 4조건 충족: S3 3.5.5 HRR 없는 classical, S3 3.5.6 HRR 있는 hybrid, S1/S2 문서상 대조, 각 조합 10회 일관).
- [x] **C: 규범 분석** — RFC 8446 §4.1.1/§4.2.7/OpenSSL 문서 인용·해석 완료. 결론: RFC 8446 위반이 아니라 OpenSSL이 `DEFAULT` 확장에서 자신이 문서화한 tuple 정책을 스스로 지키지 못한 구현 결함.
- [x] **D: 논문·재현 패키지·추적 문서 갱신** — `docs/PAPER.md`를 v1.2 주 결과로 재작성(v1.1은 선행 관측으로 보존), `tools/make_repro_package.py`를 `package=` 축으로 확장, `dist/pq-hybrid-downgrade-v12-repro.zip` 빌드·검증(`ok=True`), `docs/research/REPRODUCTION.md`에 v1.2 절 추가, 추적 문서(STATE/PROGRESS/ROADMAP) 갱신.

[확실] v1.2 작업은 완료됐습니다: 60회 실행 전부 `precondition/n=10/10`, `CVE-2026-2673 verdict: reproduced`, 논문·재현 ZIP·추적 문서 갱신 완료. 전체 테스트 `121 passed, 1 skipped`(v1.2 Task 10 시작 시점 베이스라인 `119 passed, 1 skipped`). 근거: [08-01-SUMMARY.md](phases/08-v12-cve-tuple-hrr/08-01-SUMMARY.md), [v1.2-analysis.md](../docs/research/v1.2-analysis.md), [v1.2-normative-analysis.md](../docs/research/v1.2-normative-analysis.md).

[불확실] v1.2 결과는 시험한 두 OpenSSL 버전(3.5.5/3.5.6)·group-list 설정(S1–S3)·client preference·loopback 환경·10회 반복에 한정됩니다. 모든 OpenSSL 배포·구성이나 실배포 공격 가능성을 일반화하지 않으며, S1은 CVE 증거로 쓰지 않습니다.

## v1.1 final status (2026-09-28)

- [x] **P1: tooling extension** — completed.
- [x] **P2: repeated execution** — final dataset validated (90 records).
- [x] **P3: analysis** — final raw-data analysis completed with a bounded interpretation.
- [x] **P4: paper/reproduction update** — v1.1-only paper, safe reproduction guide, and validated ZIP completed.

[확실] The v1.1 work is complete: P4 validated 90 final JSON records across nine complete r01–r10 groups, all required artifacts, and the reproduction ZIP. Its evidence and interpretation boundary are recorded in [07-04-SUMMARY.md](phases/07-v11-tooling/07-04-SUMMARY.md).

[불확실] The completed publication does not establish RFC non-conformance, CVE equivalence, practical exploitability, or a new vulnerability.

[확실] 아래의 P2/P3 항목은 당시 인계 근거를 보존한 역사 기록이며, 현재 상태는 위의 P4 완료 기록이 기준입니다.

## v1.1 P2/P3 Historical Handoff Record (2026-09-25)

- [x] **P2: repeated execution** — the clean WSL run produced 90 validated JSON records (9 combinations × r01–r10), with all required PCAP/client/capture artifacts present and `manipulation_verified=True` for every record.
- [x] **P3: analysis** — subsequently completed with a bounded interpretation of the final raw data.
- [x] **P4: paper/reproduction update** — subsequently completed after P3 with the v1.1-only paper, guide, and validated ZIP.

Details: [P2 execution summary](phases/07-v11-tooling/07-02-SUMMARY.md).

[확실] **P3 historical completion record (2026-09-25):** P3 recomputed the final 90-record dataset and recorded a bounded interpretation in [v1.1-p3-analysis.md](../docs/research/v1.1-p3-analysis.md). P4 subsequently updated the paper and reproduction package; see [07-04-SUMMARY.md](phases/07-v11-tooling/07-04-SUMMARY.md).

## Overview

Phase 0(기획)에서 확정된 테스트 가능한 가설을 출발점으로, 문헌으로 근거를 다지고(1) → 3개 독립 구현의 로컬 테스트베드를 세우고(2) → 협상 필드를 조작하는 결함 주입 도구와 관측 하네스를 만들고(3) → 조합당 ≥10회 반복 실행으로 원시 데이터를 수집하고(4) → 교차 구현 비교로 가설을 판정하고(5) → 논문과 단일 ZIP 재현 패키지로 마무리(6)한다. 종착점은 "협상 로직 결함발 하이브리드-PQ 다운그레이드가 일회성 버그인가 교차 구현 패턴인가"에 증거로 답하는 완성된 논문이다.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

> Phase 0 (기획/planning) 완료 — PROPOSAL.md 산출. 로드맵은 Phase 1부터 실행한다.

- [x] **Phase 1: 문헌 조사** - 선행연구 존재 검증 + 기준 사례 CVE-2026-2673 소스 수준 분석
- [x] **Phase 2: 실험 환경 구축** - 3개 독립 하이브리드-KEM 구현 로컬 빌드 + 정상 핸드셰이크 기준선 (completed 2026-09-22)
- [x] **Phase 3: 실험 도구 개발** - MITM Fault Injector(2 결함 유형) + 지표 자동 수집 하네스
 (completed 2026-09-23)
- [x] **Phase 4: 실험 실행** - 설계 고정 후 구현(3)×결함유형(2) 조합당 ≥10회 반복 실행 (completed 2026-09-23)
- [x] **Phase 5: 결과 분석** - 교차 구현 비교로 가설(버그 대 패턴) 판정 (completed 2026-09-23)
- [x] **Phase 6: 논문 작성·제출** - 논문 + 단일 ZIP 재현 패키지 + AI/본인 판단 공개 (completed 2026-09-23)

> 🎯 **밀스톤 v1.0 완료** — Phase 1~6 전부 완료. "협상 로직 결함발 하이브리드-PQ 다운그레이드가 일회성 버그인가 교차 구현 패턴인가"에 대한 증거 기반 답변이 논문·재현 패키지·AI-대-본인 판단 공개로 완성되었다.

## v1.1 확장: HRR-absence 하이브리드 다운그레이드

v1.0 완료 산출물을 보존한 채, 하이브리드 광고와 고전 key_share 우선 전송이 HRR 없이 고전 협상으로 이어지는 조건을 별도 반복 실험으로 검증했습니다. 최종 P2/P3/P4 결과는 새로운 취약점 주장을 추가하지 않고 관측 범위로만 문서화했습니다.

- [x] **P1: 도구 확장** — 조건 빌더, TLS/SSH on-path strip, 조건 적용 검증, v1.1 집계 축을 추가했습니다. (completed 2026-09-25)
- [x] **P2: 반복 실행** — WSL에서 9개 구현×조건 조합을 조합당 10회 실행하고 최종 원시 산출물을 보존했습니다. (completed 2026-09-25)
- [x] **P3: 결과 분석** — 조건별 handshake·HRR·감사 가시성·조작 적용 여부를 분석했습니다. (completed 2026-09-25)
- [x] **P4: 논문·재현 패키지 갱신** — 검증된 P2/P3 결과만 논문, 표, 재현 패키지에 반영하고 재현 ZIP을 검증했습니다. (completed 2026-09-28)

P1 인계 조건과 실행 명령은 [07-01-SUMMARY.md](phases/07-v11-tooling/07-01-SUMMARY.md)에 기록합니다.

> 🎯 **밀스톤 v1.1 완료** — P1~P4 전부 완료. v1.1의 명시적 single tuple 수락은 문서상 동작으로 해석 보강되었으며, `DEFAULT` 경로와 수정 버전 대조는 v1.2로 이연되었다.

## v1.2 확장: OpenSSL `DEFAULT` tuple-loss와 HRR 대조 (CVE-2026-2673)

v1.1이 시험하지 않은 `DEFAULT` 키워드의 tuple-loss 발현 경로를, OpenSSL 3.5.5(발현)와 3.5.6(수정 커밋 `85977e0` 이후)의 직접 대조로 분리해 시험했습니다. 판정은 설계 §2.2의 4개 조건을 모두 충족해야만 "재현"으로 씁니다.

- [x] **A-0: 사전 확인** — OpenSSL 3.5.5 native-only 재사용 PASS, 3.5.6 수정 대조군 빌드 PASS(`fix-ancestor=yes`), BoringSSL 설정 수단 없음 확인(핵심 표본 제외). (completed 2026-09-28)
- [x] **A-1: 필수 실험 행렬** — 고정 클라이언트로 S1/S2/S3 × 3.5.5/3.5.6 × 10회 = 60회 실행, PCAP HRR 주 판정. (completed 2026-09-28)
- [x] **B: 판정** — `analyze --v12` → `CVE-2026-2673 verdict: reproduced`. (completed 2026-09-28)
- [x] **C: 규범 분석** — RFC 8446·OpenSSL 문서 인용·해석, CVE를 RFC 위반이 아닌 OpenSSL 자체 tuple 정책 위반 구현 결함으로 위치. (completed 2026-09-28)
- [x] **D: 논문·재현 패키지·추적 문서 갱신** — 논문을 v1.2 주 결과로 재작성, v1.2 재현 ZIP 빌드·검증, 추적 문서 갱신. (completed 2026-09-28)

A-0 인계 조건과 실행 명령은 [08-01-SUMMARY.md](phases/08-v12-cve-tuple-hrr/08-01-SUMMARY.md)에 기록합니다.

> 🎯 **밀스톤 v1.2 완료** — A-0~D 전부 완료. "이 고정된 테스트베드에서 CVE-2026-2673 발현 조건과 수정 대조를 재현했다."

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
**Plans**: [Phase 2 실험 환경 구축 계획](phases/02-testbed/02-01-PLAN.md)

### Phase 3: 실험 도구 개발
**Goal**: TLS 레코드 계층을 가로채 협상 필드를 조작하는 MITM Fault Injector와, 관측 지표를 자동 수집하는 결과 하네스를 만든다.
**Depends on**: Phase 2
**Requirements**: REQ-fault-injector, REQ-observation-metrics
**Success Criteria** (what must be TRUE):
  1. 두 결함 유형(그룹 목록 조작, 결합자 바인딩 위반)을 세 구현 각각에 적용할 수 있다.
  2. 조작이 실제로 적용됐는지 확인하는 검증 스크립트가 도구 버그와 진짜 "무결함" 결과를 구분한다.
  3. 매 실행마다 세 관측 지표(협상 결과 그룹, 감사 도구 탐지, 핸드셰이크 성공/실패)가 구조화된 원시 데이터로 자동 기록된다.
**Plans**: [Phase 3 실험 도구 개발 계획](phases/03-tooling/03-01-PLAN.md) · [완료 요약](phases/03-tooling/03-01-SUMMARY.md)

### Phase 4: 실험 실행
**Goal**: 실행 전 실험 설계를 고정하고, 구현(3)×결함유형(2) 조합을 조합당 최소 10회 반복 실행하여 모든 원시 데이터를 보존한다.
**Depends on**: Phase 3
**Requirements**: REQ-repeated-execution
**Success Criteria** (what must be TRUE):
  1. 원시 데이터 개수가 설계된 표본 크기와 일치한다.
  2. 파일명/메타데이터가 구현·결함유형·반복번호·실행조건을 인코딩한다.
  3. 절차가 제3자에 의해 재현 가능하다.
  4. 실행 중 설계 변경은 시점/내용/이유와 함께 기록되며, 기존 원시 데이터는 삭제되지 않는다.
**Plans**: [Phase 4 실험 실행 계획](phases/04-execution/04-01-PLAN.md) · [완료 요약](phases/04-execution/04-01-SUMMARY.md)

### Phase 5: 결과 분석
**Goal**: 원시 데이터를 구현별 비교로 정리하고 가설을 판정한다 — 협상 로직발 하이브리드-PQ 다운그레이드가 단일 라이브러리 버그인가 독립 코드베이스 전반의 패턴인가.
**Depends on**: Phase 4
**Requirements**: REQ-cross-implementation-analysis, REQ-hypothesis-lock
**Success Criteria** (what must be TRUE):
  1. 무엇이 무엇에 영향을 주는지 한 문장으로 보이는 테스트 가능한 가설과, 버그-대-패턴으로 좁혀진 연구 질문이 명시되어 있다.
  2. 구현별 비교 표/그래프가 작성되고, 각 판정이 근거한 원시 데이터 값이 인용되어 있다.
  3. 가설과 어긋나는 결과가 누락 없이 포함되고, 각 divergence마다 후보 원인이 최소 1개 기록되어 있다.
  4. 결론은 원시 데이터에 없는 주장을 하지 않으며, 한계가 명시되어 있다.
**Plans**: [Phase 5 결과 분석 계획](phases/05-analysis/05-01-PLAN.md) · [완료 요약](phases/05-analysis/05-01-SUMMARY.md)

### Phase 6: 논문 작성·제출
**Goal**: 논문 + 재현 패키지 + AI/본인 판단 공개를 한 세트로 묶어 제출한다.
**Depends on**: Phase 5
**Requirements**: REQ-reproduction-package
**Success Criteria** (what must be TRUE):
  1. 서론/방법/결과/논의 구성의 완성된 논문과 통합 참고문헌, 문제/방법/결과를 담은 ~10줄 초록, 표지가 존재한다.
  2. 원시 데이터 + 결함 주입 스크립트 + 실행 절차가 단일 ZIP 재현 패키지로 묶여 있고, 다른 위치에서 풀어도 파일 누락이 없다.
  3. 3줄 AI-대-본인 판단 공개가 포함되어 있다.
  4. 미완성 표시나 플레이스홀더가 남아 있지 않다.
**Plans**: [Phase 6 논문 작성·제출 계획](phases/06-paper/06-01-PLAN.md) · [완료 요약](phases/06-paper/06-01-SUMMARY.md)

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5 → 6

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. 문헌 조사 | 1/1 | Complete | 2026-09-22 |
| 2. 실험 환경 구축 | 1/1 | Complete   | 2026-09-22 |
| 3. 실험 도구 개발 | 1/1 | Complete | 2026-09-23 |
| 4. 실험 실행 | 1/1 | Complete | 2026-09-23 |
| 5. 결과 분석 | 1/1 | Complete | 2026-09-23 |
| 6. 논문 작성·제출 | 1/1 | Complete | 2026-09-23 |
