# Phase 5 완료 요약 — 결과 분석

완료일: 2026-09-23

## 완료 근거

- [확실] `docs/research/phase-5-analysis.md`의 "가설" 절에 한 문장 테스트 가능 가설("협상 로직 결함... 특정 라이브러리의 우연한 버그가 아니라 독립 코드베이스 전반의 패턴이다")이, "연구 질문" 절에 버그-대-패턴으로 좁혀진 질문이 명시되어 있습니다.
- [확실] 같은 문서의 "구현체별 비교" 표는 `tools/faultinject/analyze.py`로 생성되었으며, boringssl/openssh/openssl × binding/group-list 6행 모두 원시 데이터 값(`verified/n`, `success`, `failure`, `downgrade`, `negotiated group(s)`)을 인용합니다.
- [확실] "판정" 절은 group-list 벡터(세 구현 모두 10/10 다운그레이드, `negotiated_group=X25519` 또는 `curve25519-sha256`)와 binding 벡터(세 구현 모두 10/10 거부)를 원시 파일 경로(`docs/research/baselines/raw/phase-4/{boringssl,openssh,openssl}_{group-list,binding}_r0{1..10}_default.json`)와 함께 판정합니다.
- [확실] "Divergence와 후보 원인" 절은 두 divergence(A: binding이 가설의 다운그레이드 기대와 반대로 전원 거부, B: group-list 다운그레이드가 CVE-2026-2673과 달리 가시적)를 각각 후보 원인 최소 1개와 함께 기록하며, 기대/비기대 표로 누락 없이 정리합니다.
- [확실] "결론" 절은 원시 데이터(각 10/10, 총 30/30)로 뒷받침되는 범위 내에서만 주장하며, "한계" 절에 4개 한계(on-path MITM 아님, 가시성 차이, binding 프록시의 강제 무결성 실패, 로컬/3구현/고정버전 한정)를 명시합니다. 문서 끝 "자체 점검" 단락이 결론·한계의 모든 문장이 원시 데이터에서 직접 도출되었음을 재확인합니다.

## ROADMAP Phase 5 기준 대조 (4/4 충족)

1. **한 문장 테스트 가능 가설 + 버그-대-패턴 연구 질문**: 충족 — `phase-5-analysis.md` "가설"·"연구 질문" 절.
2. **구현체별 비교 표/그래프 + 원시 데이터 값 인용**: 충족 — "구현체별 비교" 표(`analyze.py` 생성) + "판정" 절의 파일 경로 인용.
3. **어긋나는 결과 누락 없이 포함 + divergence별 후보 원인 ≥1**: 충족 — "Divergence와 후보 원인" 절(Divergence A, B 각각 후보 원인 1개 이상) + 기대/비기대 표.
4. **결론이 원시 데이터 밖 주장을 하지 않고 한계 명시**: 충족 — "결론" 절 + "한계" 절(4개) + "자체 점검" 단락.

## 핵심 결과 (원시 근거)

- [확실] **group-list 벡터**: 세 독립 구현(OpenSSL, BoringSSL, OpenSSH) 전부 조합당 10/10, 총 30/30에서 하이브리드 그룹이 고전 전용 그룹으로 협상됨(`downgrade_visible=true`, `manipulation_verified=true`). → 교차 구현 **패턴**.
- [확실] **binding 벡터**: 세 구현 전부 조합당 10/10, 총 30/30에서 `handshake_result=failure`. → 결합자 바인딩 위반은 세 구현 모두에서 **거부**(다운그레이드로 이어지지 않음).
- [확실] **종합 판정**: 가설은 벡터에 따라 부분적으로 지지됨 — group-list는 패턴, binding은 보편적 방어. 두 결함 유형을 하나로 묶어 지지되지 않음이 핵심 발견.

## Phase 6 인계 조건

Phase 6(논문 작성·제출)은 아래를 그대로 사용한다.

- [확실] **논문 서론에 들어갈 것**: 연구 질문(협상 결함 → 하이브리드-PQ 다운그레이드가 단일 라이브러리 버그인가 교차 구현 패턴인가) 및 증명된-안전(Bhargavan et al., Transcript-Bound Combiners, 2026-09) 대 배포된-안전의 구분(`phase-5-analysis.md` "증명된-안전 대 배포된-안전" 절).
- [확실] **방법에 들어갈 것**: 6조합(구현 3 × 결함유형 2) × 10회 loopback 실험 설계(Phase 4), `tools/faultinject/analyze.py`로 생성한 비교표 생성 절차.
- [확실] **결과에 들어갈 것**: 구현체별 비교 표 전체(6행), group-list 30/30 다운그레이드(패턴), binding 30/30 거부(보편적 방어), 두 divergence(A: binding 전원 거부, B: 다운그레이드 가시성).
- [확실] **논의에 들어갈 것**: "종합 판정"(가설은 벡터별 부분 지지)과 "결론" 절 전문, 특히 두 결함 유형이 상반된 결과를 낸다는 것이 핵심 발견이라는 프레이밍.
- [확실] **4개 한계**(그대로 인용): (1) group-list는 on-path MITM이 아닌 CLI 자기제한, (2) 다운그레이드 가시성이 CVE-2026-2673의 조용한 폴백과 다름, (3) binding 프록시가 무결성 실패를 강제해 "조용한 수용" 존재 여부는 미관측, (4) 로컬 loopback·3구현·고정버전에 한정되어 일반화 불가.
- [확실] **원시 데이터 인용 위치**: `docs/research/baselines/raw/phase-4/`(실행당 JSON 60개 + 로그/pcap), `docs/research/baselines/raw/phase-4/manifest.csv`(조합별 집계), `tools/faultinject/analyze.py`(비교표 재생성 스크립트 — 재현 패키지에 포함 필요).
- [확실] **Phase 6이 준비해야 할 항목**: ROADMAP Phase 6 기준 3 "3줄 AI-대-본인 판단 공개"(AI-대-본인 판단 공개)를 논문에 포함해야 하며, 이 요약에는 아직 작성되지 않음 — Phase 6 작업 시 신규 작성 필요.

## 원시 데이터 위치

- [확실] `docs/research/baselines/raw/phase-4/` — 실행당 JSON(60개)·로그·pcap(binding 30건은 `-proxy.log` 추가).
- [확실] `docs/research/baselines/raw/phase-4/manifest.csv` — 조합별 total/verified/success/downgrade 집계.
- [확실] `tools/faultinject/analyze.py` — 원시 데이터에서 "구현체별 비교" 표를 재생성하는 스크립트.
