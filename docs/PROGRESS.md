# pq-hybrid-downgrade 진행 현황

- 마지막 업데이트: 2026-09-28
- 기획: [PROPOSAL.md](PROPOSAL.md) · 로드맵: [.planning/ROADMAP.md](../.planning/ROADMAP.md) · 상태: [.planning/STATE.md](../.planning/STATE.md)
- **현재 Phase:** 완료 — v1.2 밀스톤 전체 완료 (A-0~D). 브랜치 `v1.2-cve-tuple-hrr`, main 미병합

## 🎯 밀스톤 v1.2 완료

v1.1이 시험하지 않은 OpenSSL `DEFAULT` 키워드의 group tuple-loss 발현 경로(CVE-2026-2673)를, OpenSSL 3.5.5(발현)와 3.5.6(수정 커밋 `85977e0` 이후)의 직접 대조로 분리해 시험했습니다. 고정된 OpenSSL 3.5.5 native-only 클라이언트로 서버 group-list 설정(S1 `X25519MLKEM768:X25519`, S2 `X25519MLKEM768/X25519`, S3 `DEFAULT`) × 서버 버전 2 × 10회 = 60회를 실행했습니다. [설계 스펙](superpowers/specs/2026-09-28-v12-cve-tuple-hrr-design.md)

| 상태 | 단계 | 산출물 |
|---|---|---|
| 완료 | A-0 사전 확인 | [A-0 환경 대장](research/v1.2-a0-environment.md) |
| 완료 | A-1 필수 실험 행렬 | [원시 데이터 60건](research/baselines/raw/v1.2/), [결과 분석](research/v1.2-analysis.md) |
| 완료 | B 판정 | `CVE-2026-2673 verdict: reproduced`([결과 분석 §4](research/v1.2-analysis.md)) |
| 완료 | C 규범 분석 | [RFC 8446·OpenSSL 정책 분석](research/v1.2-normative-analysis.md) |
| 완료 | D 논문·재현 패키지·추적 문서 갱신 | [논문](PAPER.md), [재현 절차](research/REPRODUCTION.md), [v1.2 재현 ZIP](../dist/pq-hybrid-downgrade-v12-repro.zip), [완료 요약](../.planning/phases/08-v12-cve-tuple-hrr/08-01-SUMMARY.md) |

### v1.2 결과 요약

- [확실] **판정:** `python -m faultinject.analyze --v12`(tools/에서 실행) → `CVE-2026-2673 verdict: reproduced`. S3(`DEFAULT`)에서 3.5.5는 10/10 PCAP HRR 없이 classical(`X25519`) 완료, 3.5.6은 10/10 PCAP HRR 있음 + hybrid(`X25519MLKEM768`) 완료. 설계 §2.2의 4개 판정 조건 모두 충족.
- [확실] **S1/S2 대조:** S1(명시적 single tuple)은 두 버전 모두 HRR 없음·classical(문서상 동작, CVE 증거 아님). S2(명시적 tuple 경계)는 두 버전 모두 HRR 있음·hybrid.
- [확실] **규범 분석:** RFC 8446 §4.1.1의 MUST-HRR은 클라이언트가 호환 key_share를 보내지 않았을 때만 적용되는 조건부 의무이므로 S1·S3(3.5.5)는 RFC 위반이 아닙니다. CVE-2026-2673은 OpenSSL이 `DEFAULT` 확장에서 자신이 문서화한 tuple 기반 group-selection 정책을 스스로 지키지 못한 구현 결함으로 위치합니다.
- [확실] **감사 가시성:** v1.2 60건 전부 `explicit_warning=False`, `mismatch_in_single_output=False`(도구 한계로 unsupported). v1.1 90건 재계산도 동일한 한계(OpenSSH 30건만 True, TLS 60건 unsupported).
- [확실] **BoringSSL:** A-0 조사 결과 OpenSSL `DEFAULT`/tuple 구문에 대응하는 설정 수단이 없어 핵심 CVE 표본에서 제외. v1.1 BoringSSL `silent-downgrade`의 key_share는 실제로 두 개([0x001D, 0x6399])였다는 사실이 새로 확인됨.
- [불확실] 결과는 시험한 두 OpenSSL 버전·group-list 설정·client preference·loopback 환경·10회 반복에 한정됩니다. 모든 OpenSSL 배포로 일반화하지 않으며, S1은 CVE 증거로 쓰지 않습니다.

### v1.2 완료 기록

- [확실] A-0/설계: `cf4e029`~`8ccbc6a` — v1.2 설계·구현 계획, A-0 환경 대장(3.5.5 재사용 PASS, 3.5.6 빌드 PASS `fix-ancestor=yes`, BoringSSL 조사).
- [확실] 도구: `ebdba92`~`f99f79b` — PCAP 기반 TLS Hello/HRR 파서, 서버-설정 행렬 CLI(`faultinject.v12`), preflight, 경로별 감사 가시성 측정 도구(`audit.py`).
- [확실] 실행·판정: `c2ac148`~`6d4288b` — v1.1 90건 감사 가시성 재계산, 60회 실행 수집·집계·CVE 판정 규칙 인코딩.
- [확실] 규범 분석: `b4a3769` — RFC 8446·OpenSSL 문서 정책 정규 분석.
- [확실] Task 10(D): 논문을 v1.2 주 결과로 재작성(v1.1은 선행 관측으로 보존), `make_repro_package.py`를 `package=` 축으로 확장(v1.1 회귀 없음), v1.2 재현 ZIP 빌드·검증(`ok=True`), `REPRODUCTION.md`·추적 문서 갱신. 전체 테스트 `121 passed, 1 skipped`(베이스라인 `119 passed, 1 skipped`).

## 밀스톤 v1.1 완료 (이전 기록)

v1.0 결론(group-list는 클라이언트 자기 제한에 가까운 동어반복, CVE-2026-2673의 `DEFAULT` 경로 미시험)을 보완하기 위해, 하이브리드를 광고한 상태에서 `key_share` 순서가 협상·HRR·감사 가시성에 미치는 영향을 교차 구현으로 재측정했습니다. OpenSSL의 v1.1 single tuple 수락은 문서상 정상 동작으로 해석 보강했으며, `DEFAULT` 경로와 수정 버전 대조는 후속 v1.2 범위입니다. [설계 스펙](research/2026-09-23-v1.1-hrr-downgrade-design.md)

| 상태 | 단계 | 산출물 |
|---|---|---|
| 완료 | P1 도구 확장 | [계획](../.planning/phases/07-v11-tooling/07-01-PLAN.md), [완료 요약](../.planning/phases/07-v11-tooling/07-01-SUMMARY.md) |
| 완료 | P2 재실행 | [원시 데이터 90건](research/baselines/raw/v1.1/), [완료 요약](../.planning/phases/07-v11-tooling/07-02-SUMMARY.md) |
| 완료 | P3 재분석 | [분석 문서](research/v1.1-p3-analysis.md), [완료 요약](../.planning/phases/07-v11-tooling/07-03-SUMMARY.md) |
| 완료 | P4 논문·패키지 | [논문](PAPER.md), [재현 절차](research/REPRODUCTION.md), [v1.1 재현 ZIP](../dist/pq-hybrid-downgrade-v11-repro.zip), [완료 요약](../.planning/phases/07-v11-tooling/07-04-SUMMARY.md) |

### v1.1 결과 요약

- [확실] 9개 구현×조건 조합 × 10회 = JSON 90건, 전부 `manipulation_verified=true`.
- [확실] **classical-first `key_share` (하네스 ID: `silent-downgrade`):** OpenSSL·BoringSSL 각각 10/10 성공, 고전 `X25519` 협상, HRR 0(PCAP 교차 검증), 자동 flag 0. OpenSSL의 명시적 single tuple 수락은 문서상 선택 규칙과 일치합니다.
- [확실] **onpath-strip (A):** 두 TLS 구현 각각 10/10 핸드셰이크 실패(fail-closed). OpenSSL은 HRR 뒤 `bad_record_mac`으로 중단.
- [확실] **OpenSSH:** 구조적 대조군으로만 해석(key_share/HRR 없음). base·ssh-order 하이브리드 KEX 유지, onpath-strip 연결 실패.
- [불확실] RFC 비준수, CVE 재현, 실배포 공격 가능성은 주장하지 않습니다.

### v1.1 완료 기록

- [확실] P1: `0c0f0c3`~`4b39e25` — 조건 빌더, TLS/SSH strip, HRR·감사 가시성 지표, `verify_condition()`, `--v11` CLI, 조건 축 집계·분석.
- [확실] P2: `b4c598a` — WSL 반복 실행, 90건 수집·검증(분리 실행 timeout은 클라이언트 stdin EOF 처리로 해결).
- [확실] P3: `c1427fa` — 최종 90건만으로 분석, 진단/프리플라이트 디렉터리 제외.
- [확실] P4: `d07b754`~`4d407fa` — v1.1 논문·재현 가이드 게시, v1.1 재현 ZIP 빌드·검증.
- [확실] 2026-09-28 정정: 수집 당시 `detect_hrr()`가 OpenSSL `-msg`의 HRR(`ServerHello`로 표기)을 놓쳐 OpenSSL onpath-strip의 `hrr_present`가 0으로 기록됨. PCAP의 RFC 8446 HRR 고정 random으로 교차 검증해 논문 표를 10/10으로 정정했고, 원시 JSON은 수정하지 않음. 파서를 고정 random 매칭으로 수정, 테스트 69 passed / 1 skipped, ZIP 재빌드 `ok=True`. silent-downgrade의 HRR 0 결론은 PCAP으로 독립 확인되어 영향 없음.

## 밀스톤 v1.0 완료 (이전 기록)

전체 프로젝트(Phase 1~6)가 완료되어, "협상 로직 결함발 하이브리드-PQ 다운그레이드가 일회성 버그인가 교차 구현 패턴인가"에 대한 증거 기반 답변이 논문·재현 패키지·AI-대-본인 판단 공개로 완성되었습니다.

## 완료 현황

| 상태 | Phase | 산출물 |
|---|---|---|
| 완료 | 1. 문헌 조사 | [phase-1-synthesis.md](research/phase-1-synthesis.md) |
| 완료 | 2. 실험 환경 구축 | [환경 대장](research/phase-2-environment.md), [baseline](research/baselines/), [검증 보고서](../.planning/phases/02-testbed/02-VERIFICATION.md) |
| 완료 | 3. 실험 도구 개발 | [설계](research/phase-3-experiment-design.md), [도구](../tools/faultinject/), [완료 요약](../.planning/phases/03-tooling/03-01-SUMMARY.md) |
| 완료 | 4. 실험 실행 | [실행 기록](research/phase-4-execution.md), [원시 데이터](research/baselines/raw/phase-4/), [manifest](research/baselines/raw/phase-4/manifest.csv), [완료 요약](../.planning/phases/04-execution/04-01-SUMMARY.md) |
| 완료 | 5. 결과 분석 | [분석 문서](research/phase-5-analysis.md), [비교표 생성 스크립트](../tools/faultinject/analyze.py), [완료 요약](../.planning/phases/05-analysis/05-01-SUMMARY.md) |
| 완료 | 6. 논문 작성·제출 | [논문](PAPER.md), [재현 절차](research/REPRODUCTION.md), [단일 ZIP 재현 패키지](../dist/pq-hybrid-downgrade-repro.zip), [완료 요약](../.planning/phases/06-paper/06-01-SUMMARY.md) |

## 다음 작업

- [확실] v1.1 밀스톤까지 완료되었습니다. 남은 결정은 `v1.1-hrr-downgrade` 브랜치의 main 병합 여부입니다.
- [확실] 후속 확장(EXPN-01 추가 구현, EXPN-02 원격/실배포 관측)과 v1.1 설계 §8의 범위 밖 항목(RFC 규범 해석, CVE-2026-2673 소스 수준 분석)은 활성 계획이 없습니다. [.planning/REQUIREMENTS.md](../.planning/REQUIREMENTS.md) 참고.

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

## Phase 4 완료 기록

- [확실] `d01ebcd`(feat(04-01): collect repeated fault-injection runs and manifest) — `python3 -m faultinject.run --repeat 10` 1회 배치로 6조합(구현 3 × 결함유형 2) × 10회 = 60건 실행 수집, `research/baselines/raw/phase-4/manifest.csv`에 조합별 total/verified/success/downgrade 집계 기록.
- [확실] `docs(04-01): complete Phase 4 execution and hand off to Phase 5` — Phase 4 완료 판정(4/4 기준 충족) 및 Phase 5 인계 조건 문서화, 추적 문서(STATE/ROADMAP/REQUIREMENTS/PROGRESS) 갱신.
- [확실] 6조합 전부 `verified=10 (≥10)`으로 표본 크기 기준 충족. `binding` 조합(3구현체 모두) `success=0`(조작 거부), `group-list` 조합(3구현체 모두) `success=10, downgrade=10`(다운그레이드 3개 구현 전부 재현).

## Phase 5 인계 조건

- [확실] 분석 대상 데이터: `research/baselines/raw/phase-4/`(원시 파일) + `research/baselines/raw/phase-4/manifest.csv`(집계).
- [확실] 기준 협상값: OpenSSL `X25519MLKEM768`, BoringSSL `X25519Kyber768Draft00`, OpenSSH `sntrup761x25519-sha512@openssh.com`.
- [확실] REQ-cross-implementation-analysis 요구에 따라 가설과 어긋나는 결과(예: `binding` 조합의 `success=0`)도 누락 없이 포함하고 divergence마다 후보 원인을 최소 1개 기록해야 합니다.

## Phase 5 완료 기록

- [확실] `4d4aae0`(feat(05-01): add cross-implementation comparison generator and lock hypothesis) — `tools/faultinject/analyze.py`로 구현체별 비교표를 원시 데이터에서 생성하고 가설을 고정.
- [확실] `3c0000c`(docs(05-01): fix research-question section — remove backwards combiner citation) — 연구 질문 절의 콤바이너 인용 오류 수정.
- [확실] `203e7e7`(docs(05-01): judge hypothesis with cited data, divergences, conclusion, limits) — 판정·divergence·결론·한계 4개 절 완성.
- [확실] `docs(05-01): complete Phase 5 analysis and hand off to Phase 6` — Phase 5 완료 판정(4/4 기준 충족) 및 Phase 6 인계 조건 문서화, 추적 문서(STATE/ROADMAP/REQUIREMENTS/PROGRESS) 갱신.
- [확실] group-list 벡터: 세 구현 전부 10/10(총 30/30) 하이브리드→고전 다운그레이드 — 교차 구현 패턴. binding 벡터: 세 구현 전부 10/10(총 30/30) 거부 — 보편적 방어. 가설은 벡터별로 부분 지지.

## Phase 6 인계 조건

- [확실] 논문 서론/방법/결과/논의에 들어갈 핵심 결과: `docs/research/phase-5-analysis.md`의 "구현체별 비교" 표, "판정", "Divergence와 후보 원인", "결론" 절 전문.
- [확실] 4개 한계(그대로 인용): on-path MITM 아님, 다운그레이드 가시성이 CVE-2026-2673과 다름, binding 프록시의 강제 무결성 실패로 "조용한 수용" 미관측, 로컬 loopback·3구현·고정버전 한정.
- [확실] 원시 데이터 인용 위치: `research/baselines/raw/phase-4/`(JSON 60개+로그/pcap), `research/baselines/raw/phase-4/manifest.csv`(집계), `../tools/faultinject/analyze.py`(비교표 재생성 스크립트).
- [확실] Phase 6은 ROADMAP 기준 3에 따라 3줄 "AI-대-본인 판단 공개"를 신규 작성해야 합니다(Phase 5까지는 아직 작성되지 않음).

## Phase 6 완료 기록

- [확실] `b115e48`(docs(06-01): scaffold paper, fix citation attribution, finalize references) — 논문 표지·구조 스캐폴드, 참고문헌 귀속 수정, 통합 참고문헌 확정.
- [확실] `4a9780b`(docs(06-01): write paper body and abstract from verified artifacts) — 검증된 산출물(Phase 4 원시 데이터, Phase 5 분석)로부터 논문 초록·서론·방법·결과·논의 작성.
- [확실] `4f89f2f`(feat(06-01): add single-ZIP reproduction package builder and verifier) — `tools/make_repro_package.py`로 단일 ZIP 재현 패키지 생성·검증 스크립트 구현.
- [확실] `docs(06-01): add AI-vs-human disclosure, finalize paper, complete milestone` — 3줄 AI-대-본인 판단 공개 작성, 최종 무결성 점검(플레이스홀더 없음 확인, 결과 수치-manifest 대조, `verify_zip` → `(True, [])`, `pytest -q` → 42 passed/1 skipped), 추적 문서(STATE/ROADMAP/REQUIREMENTS/PROGRESS) 갱신 및 v1.0 밀스톤 완료 판정.
- [확실] **최종 결론**: group-list 조작은 세 독립 구현(OpenSSL, BoringSSL, OpenSSH) 전반의 패턴(30/30 다운그레이드)이며, 컴바이너 바인딩 위반은 세 구현 모두 방어에 성공(0/30 다운그레이드)했습니다. 가설은 결함 유형에 따라 부분적으로만 지지됩니다.
