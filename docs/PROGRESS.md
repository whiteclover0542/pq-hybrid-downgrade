# pq-hybrid-downgrade 진행 현황

- 마지막 업데이트: 2026-09-23
- 기획: [PROPOSAL.md](PROPOSAL.md) · 로드맵: [.planning/ROADMAP.md](../.planning/ROADMAP.md) · 상태: [.planning/STATE.md](../.planning/STATE.md)
- **현재 Phase:** Phase 6 — 논문 작성·제출

## 완료 현황

| 상태 | Phase | 산출물 |
|---|---|---|
| 완료 | 1. 문헌 조사 | [phase-1-synthesis.md](research/phase-1-synthesis.md) |
| 완료 | 2. 실험 환경 구축 | [환경 대장](research/phase-2-environment.md), [baseline](research/baselines/), [검증 보고서](../.planning/phases/02-testbed/02-VERIFICATION.md) |
| 완료 | 3. 실험 도구 개발 | [설계](research/phase-3-experiment-design.md), [도구](../tools/faultinject/), [완료 요약](../.planning/phases/03-tooling/03-01-SUMMARY.md) |
| 완료 | 4. 실험 실행 | [실행 기록](research/phase-4-execution.md), [원시 데이터](research/baselines/raw/phase-4/), [manifest](research/baselines/raw/phase-4/manifest.csv), [완료 요약](../.planning/phases/04-execution/04-01-SUMMARY.md) |
| 완료 | 5. 결과 분석 | [분석 문서](research/phase-5-analysis.md), [비교표 생성 스크립트](../tools/faultinject/analyze.py), [완료 요약](../.planning/phases/05-analysis/05-01-SUMMARY.md) |
| 예정 | 6. 논문 작성·제출 | Phase 5 이후 |

## 다음 작업

- [ ] Phase 6 계획 작성: 논문(서론/방법/결과/논의) + 단일 ZIP 재현 패키지 + 3줄 AI-대-본인 판단 공개를 산출합니다.

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
