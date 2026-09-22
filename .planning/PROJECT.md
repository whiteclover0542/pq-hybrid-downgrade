# pq-hybrid-downgrade

## What This Is

포스트퀀텀 하이브리드 키 교환의 다운그레이드 저항성 — 증명된 설계와 실제 구현 사이의 간극.
하이브리드 PQ 키 교환의 다운그레이드 저항성은 프로토콜 설계 수준에서 형식적으로 증명되어 있다. 이 연구는 배포된 구현들이 실제로 그 증명을 지키는지를 경험적으로 시험하고, 협상 로직 결함으로 인한 하이브리드-PQ 다운그레이드가 단일 라이브러리 버그인지 여러 구현에 걸친 패턴인지를 밝히는 단독 저자 보안 연구 프로젝트다.

## Core Value

증거로 뒷받침된 결론 — "협상 로직 결함발(發) 하이브리드-PQ 다운그레이드가 일회성 라이브러리 버그인가, 교차 구현 패턴인가" — 에 답하는 완성된 논문과 재현 패키지. 다른 모든 것이 실패해도 이 결론과 그것을 뒷받침하는 원시 데이터는 반드시 성립해야 한다.

## Requirements

### Validated

<!-- Shipped and confirmed valuable. -->

- ✓ REQ (Phase 0): 기획 — 테스트 가능한 가설과 실험 설계를 담은 PROPOSAL.md 작성 완료 (2026-09-22)

### Active

<!-- Current scope. Building toward these. See REQUIREMENTS.md for full text. -->

- [ ] REQ-prior-work-verification — 선행연구 존재 검증 및 CVE-2026-2673 소스 수준 분석
- [ ] REQ-testbed-three-implementations — 3개 독립 하이브리드-KEM 구현 로컬 구축 + 정상 핸드셰이크 기준선
- [ ] REQ-fault-injector — MITM Fault Injector(2개 결함 유형) + 결과 수집 하네스
- [ ] REQ-observation-metrics — 실행마다 3개 관측 지표 원시 데이터 기록
- [ ] REQ-repeated-execution — 구현(3)×결함유형(2) 조합당 ≥10회 반복 실행 및 원시 데이터 보존
- [ ] REQ-cross-implementation-analysis — 교차 구현 비교 분석 및 가설 판정
- [ ] REQ-hypothesis-lock — 테스트 가능한 가설/연구 질문 고정 (버그 대 패턴)
- [ ] REQ-reproduction-package — 논문 + 단일 ZIP 재현 패키지 + AI/본인 판단 공개

### Out of Scope

<!-- Explicit boundaries. Includes reasoning to prevent re-adding. -->

- 원격/클라우드 대규모 스캔 — 로컬 연구 환경 범위. 세 구현의 통제된 로컬 실험이 버그-대-패턴 질문에 충분하다.
- 신규 다운그레이드-저항 콤바이너 설계/제안 — 이 연구는 배포 구현의 as-deployed 안전성을 경험적으로 시험할 뿐, 새 설계를 증명하지 않는다.
- 세 구현을 넘어선 추가 라이브러리 커버리지 — v1 범위는 OpenSSL+oqs-provider, BoringSSL, OpenSSH로 고정. 확장은 후속 연구.

## Context

- 단독 저자 보안 연구. 구현자는 Claude, 시각/판단 주체는 사용자.
- 동기: 저자가 운영하는 Today-CVE-information(github.com/whiteclover0542/Today-CVE-information, 2026-08-22~) 자동 수집에서 2026-08-23~09-22 협상/핸드셰이크 단계 로직 결함이 반복 관측됨.
- 기준 사례: CVE-2026-2673 (2026-03-13 공개, OpenSSL 3.5 계열) — PQ 하이브리드 그룹 협상이 표준 TLS 감사 도구가 놓치는 방식으로 조용히 classical로 다운그레이드. 이것이 주제를 버그-대-패턴 질문으로 좁혔다.
- 배경 CVE 3건 (공통점 = 결함 유형이 아니라 결함 위치가 협상/핸드셰이크 단계, 겉보기 정상): FreeRDP CVE-2026-91949, Cisco ASA/FTD IKEv2 CVE-2026-20249, NGINX+OpenSSL≤3.5.0 HTTP/3 CVE-2026-90439.
- 선행연구 근거: Bhargavan et al. 다운그레이드-저항 정의; "Transcript-Bound Combiners for Downgrade-Resilient Hybrid PQ Key Establishment" (2026-09).
- 대상 런타임: Windows 로컬 연구 환경 (Python 도구 + 로컬 빌드 OpenSSL+oqs-provider, BoringSSL, OpenSSH).
- 6단계 작업 순서는 docs/PROGRESS.md 및 docs/plans/phase-0..6-*.md에 상세. Phase 0(기획) 완료.

## Constraints

- **Environment**: Windows 로컬 연구 환경, Python 도구 + 로컬 빌드 3개 구현 — 재현 가능성과 통제된 실험을 위해.
- **Reproducibility**: 버전/커밋 해시/빌드 옵션을 정확히 고정 — 결함이 특정 버전에만 존재할 수 있고 재현에 필수.
- **Data integrity**: 모든 원시 데이터 보존, 사전 삭제 금지; 실행 중 설계 변경은 시점/내용/이유 기록 — 체리피킹 방지, 제3자 재현.
- **Tool validity**: 조작이 실제 적용됐는지 검증 스크립트로 확인 — 조용히 실패하는 도구를 "무결함"으로 오독하지 않기 위해.
- **Judgment**: 결론/판정은 저자 본인이 내리고 AI에는 요약/번역만 위임 — 연구 무결성.
- **Verification of citations**: AI가 제안한 참고문헌은 할루시네이션 가능 — 각 인용을 직접 존재 검증하고 방법 기록.

## Key Decisions

<!-- Decisions that constrain future work. 0 ADR-locked decisions at init — none locked yet. -->

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| 6단계 워크플로 유지 (문헌→환경→도구→실행→분석→집필) | 소스 문서가 이미 검증된 순서를 정의; 자연스러운 산출물 경계 | — Pending |
| 3개 구현 고정 (OpenSSL+oqs, BoringSSL, OpenSSH) | 독립 코드베이스로 버그-대-패턴 판정에 충분 | — Pending |

---
*Last updated: 2026-09-22 after project initialization (from ingest)*
