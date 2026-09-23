# Phase 6 완료 요약 — 논문 작성·제출

완료일: 2026-09-23

## 완료 근거

- [확실] `docs/PAPER.md`는 표지(저자·날짜·한줄요약)·초록·서론·방법·결과·논의·통합 참고문헌·AI-대-본인 판단 공개 부록을 모두 갖춘 완성된 논문입니다. 초록은 문제·방법·결과·한계를 담은 단일 문단으로 ROADMAP 기준(~10줄 규모)을 충족합니다.
- [확실] 결과 절의 표(6행: `implementation × fault_type`)와 본문 수치(group-list 30/30, binding 0/30)는 `docs/research/baselines/raw/phase-4/manifest.csv`와 정확히 일치합니다(대조: boringssl/openssh/openssl × binding/group-list 각 total=10, verified=10, success/downgrade는 group-list=10·binding=0).
- [확실] 참고문헌 [1]은 Bhargavan et al. 2016(다운그레이드 저항성 정의 원 논문), [2]는 Gupta & Rana 2026(transcript-bound combiner 증명)으로, 본문 인용에서도 두 문헌의 기여가 서로 다른 문장에서 구분되어 귀속됩니다.
- [확실] `tools/make_repro_package.py`로 생성한 단일 ZIP(`dist/pq-hybrid-downgrade-repro.zip`)은 `verify_zip()`이 `(True, [])`를 반환해, 매니페스트·실행 코드·원시 phase-4 JSON 60건 이상·`REPRODUCTION.md`가 모두 포함되어 있고 어느 위치에 풀어도 상대 경로로 동작함을 확인했습니다.
- [확실] `docs/PAPER.md` 부록에 3줄 AI-대-본인 판단 공개(AI 수행 항목·사람 수행/결정 항목·검증 방식)를 작성했고, 사람의 검토·승인이 필요함을 명시하는 경고 줄을 바로 뒤에 남겼습니다(이 줄은 의도된 리뷰 표시이며 플레이스홀더가 아닙니다).
- [확실] `docs/PAPER.md`, `docs/research/REPRODUCTION.md`에 `TBD`/`TODO`/플레이스홀더 문자열이 없음을 grep으로 확인했고, 두 문서 모두 모든 섹션에 실제 내용이 있습니다(빈 섹션 없음).

## ROADMAP Phase 6 기준 대조 (4/4 충족)

1. **서론/방법/결과/논의 구성의 완성된 논문 + 통합 참고문헌 + ~10줄 초록 + 표지**: 충족 — `docs/PAPER.md` 전체 구조(표지 → 초록 → 1~4장 → 참고문헌).
2. **원시 데이터 + 결함 주입 스크립트 + 실행 절차가 단일 ZIP으로 묶여 다른 위치에서도 파일 누락 없음**: 충족 — `dist/pq-hybrid-downgrade-repro.zip`, `verify_zip()` → `(True, [])`.
3. **3줄 AI-대-본인 판단 공개 포함**: 충족 — `docs/PAPER.md`의 "부록: AI-대-본인 판단 공개"(사람 검토·승인 대기 표시 포함).
4. **미완성 표시나 플레이스홀더 없음**: 충족 — `docs/PAPER.md`·`docs/research/REPRODUCTION.md`·본 요약 문서 grep 확인, `tools`에서 `pytest -q` 42 passed / 1 skipped.

## 최종 무결성 점검 결과

- [확실] `cd tools && python -c "from make_repro_package import verify_zip; print(verify_zip('../dist/pq-hybrid-downgrade-repro.zip'))"` → `(True, [])`.
- [확실] `cd tools && python -m pytest -q` → `42 passed, 1 skipped in 0.70s`(tshark 미탑재로 인한 예상된 1건 skip).
- [확실] `docs/PAPER.md`·`docs/research/REPRODUCTION.md`·본 요약 문서에 `TBD`/`TODO`/`placeholder`/`플레이스홀더` 문자열 없음(grep 결과 없음, exit code 1).
- [확실] `docs/PAPER.md` "3. 결과" 절의 6행 표 수치가 `docs/research/baselines/raw/phase-4/manifest.csv`와 셀 단위로 일치.
- [확실] 참고문헌 [1] Bhargavan et al. 2016과 [2] Gupta & Rana 2026이 서로 다른 저자·연도·기여로 명확히 구분되어 귀속됨.

## 밀스톤 완료

- [확실] Phase 1~6(문헌 조사 → 실험 환경 구축 → 실험 도구 개발 → 실험 실행 → 결과 분석 → 논문 작성·제출) 전부 완료로, v1.0 밀스톤 "협상 로직 결함발 하이브리드-PQ 다운그레이드가 일회성 버그인가 교차 구현 패턴인가"에 대한 증거 기반 답변이 완성되었습니다.
- [확실] 핵심 결론: group-list 조작은 세 독립 구현(OpenSSL, BoringSSL, OpenSSH) 전반의 패턴(30/30 다운그레이드)이며, 컴바이너 바인딩 위반은 세 구현 모두 방어에 성공(0/30 다운그레이드)했습니다. 가설은 벡터에 따라 부분적으로만 지지됩니다.
- [확실] 다음 작업 없음 — 후속 확장(EXPN-01 추가 구현, EXPN-02 원격/실배포 관측)은 REQUIREMENTS.md v2에 이연되어 있으며 현재 로드맵에는 포함되지 않습니다.

## 산출물 위치

- [확실] 논문: `docs/PAPER.md`.
- [확실] 재현 절차: `docs/research/REPRODUCTION.md`.
- [확실] 단일 ZIP 재현 패키지: `dist/pq-hybrid-downgrade-repro.zip`(생성/검증: `tools/make_repro_package.py`).
- [확실] 원시 데이터: `docs/research/baselines/raw/phase-4/`(JSON 60개+로그/pcap) 및 `manifest.csv`.
