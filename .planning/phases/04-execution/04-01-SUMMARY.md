# Phase 4 완료 요약 — 실험 실행

완료일: 2026-09-23

## 완료 근거

- [확실] `tools/`에서 `python3 -m faultinject.run --repeat 10`을 1회 실행하여 구현(OpenSSL, BoringSSL, OpenSSH) × 결함유형(`group-list`, `binding`) 6조합 × 10회 = 60회 실행을 수집했습니다.
- [확실] `docs/research/baselines/raw/phase-4/manifest.csv`는 6조합 모두 `total=10, verified=10`을 기록합니다:

  | implementation | fault_type | total | verified | success | downgrade |
  | --- | --- | --- | --- | --- | --- |
  | boringssl | binding | 10 | 10 | 0 | 0 |
  | boringssl | group-list | 10 | 10 | 10 | 10 |
  | openssh | binding | 10 | 10 | 0 | 0 |
  | openssh | group-list | 10 | 10 | 10 | 10 |
  | openssl | binding | 10 | 10 | 0 | 0 |
  | openssl | group-list | 10 | 10 | 10 | 10 |

- [확실] `docs/research/baselines/raw/phase-4/`에 실행당 `.json`(60개), `-client.log`, `-server.log`, `-capture.log`, `.pcapng`가 존재하고, `binding` 조합 30건에는 `-proxy.log`가 추가됩니다. 파일명은 `<impl>_<fault_type>_r<NN>_<condition>` 규칙(예: `boringssl_binding_r01_default`)을 따르며 구현·결함유형·반복번호·조건을 인코딩합니다.
- [확실] 재현 절차는 `docs/research/phase-4-execution.md`의 "재현 절차" 절(프리플라이트 → `python -m faultinject.run --repeat 10` → `python -m faultinject.aggregate`)에 구체적 명령으로 기록되어 제3자가 그대로 실행할 수 있습니다.
- [확실] 실행 중 설계 변경 로그는 "변경 없음"(`docs/research/phase-4-execution.md` 설계 변경 로그 표)이며, 기존 원시 데이터를 삭제·수정하지 않았습니다(최초 배치였으므로 보존 대상 기존 파일 없음).
- [확실] `python -m pytest`(tools/) 결과 38 passed, 1 skipped(tshark 미설치로 인한 스킵)로 전체 통과입니다.

## ROADMAP Phase 4 기준 대조 (4/4 충족)

1. **원시 데이터 개수 = 설계 표본 크기**: 충족 — 6조합 × 10회 = 60건, `manifest.csv` 전 조합 `verified=10 (≥10)`.
2. **파일명/메타데이터 인코딩**: 충족 — `<impl>_<fault_type>_r<NN>_<condition>` 형식이 실제 60개 JSON 및 로그 파일에 적용됨.
3. **제3자 재현 가능 절차**: 충족 — `docs/research/phase-4-execution.md`에 프리플라이트·배치 실행·집계 명령이 순서대로 기록됨.
4. **설계 변경 기록 + 원시 데이터 미삭제**: 충족 — 설계 변경 로그에 "변경 없음"이 시점과 함께 명시됨, 삭제된 원시 파일 없음.

## 결과 해석 (데이터이지 오류가 아님)

- [확실] `binding` 조합(3구현체 모두): `success=0`. MITM 프록시가 하이브리드 교환의 PQ 성분을 위조했으나 3개 구현 모두 핸드셰이크를 거부했습니다. 이는 하이브리드 바인딩이 조작을 탐지·거부했다는 측정 결과입니다.
- [확실] `group-list` 조합(3구현체 모두): `success=10, downgrade=10`. 하이브리드 그룹을 제외한 제안이 3개 구현 전부에서 100% classical-only로 다운그레이드되었습니다. 다운그레이드가 단일 구현의 버그가 아니라 3개 독립 코드베이스에서 재현된다는 것을 의미합니다(Phase 5 판정의 원시 근거).

## 원시 데이터 위치

- [확실] `docs/research/baselines/raw/phase-4/` — 실행별 JSON·클라이언트/서버 로그·pcap·캡처 로그, binding 조합은 `-proxy.log` 추가.
- [확실] `docs/research/baselines/raw/phase-4/manifest.csv` — 조합별 total/verified/success/downgrade 집계.

## Phase 5 인계 조건

- [확실] **분석 대상 데이터 위치**: `docs/research/baselines/raw/phase-4/`(원시 파일 전체)와 `docs/research/baselines/raw/phase-4/manifest.csv`(조합별 집계)를 분석 입력으로 사용합니다.
- [확실] **조합별 검증 표본 수**: 6조합 모두 `verified=10`(boringssl/openssh/openssl × binding/group-list). 표본 크기 미달 조합 없음.
- [확실] **기준 협상값**(`docs/research/phase-4-execution.md`): OpenSSL `X25519MLKEM768`, BoringSSL `X25519Kyber768Draft00`, OpenSSH `sntrup761x25519-sha512@openssh.com`. Phase 5의 다운그레이드 판정은 이 값과 실제 협상 그룹의 불일치 여부로 이루어져야 합니다.
- [확실] **누락 없는 divergence 포함 요구**: Phase 5는 REQ-cross-implementation-analysis에 따라 가설(단일 버그 대 교차 구현 패턴)과 어긋나는 결과도 누락 없이 포함하고, 각 divergence마다 후보 원인을 최소 1개 기록해야 합니다. `binding` 조합의 `success=0`(다운그레이드 실패, 즉 가설상 "성공적 조작"과 반대되는 결과)이 그러한 사례이며 원시 데이터(JSON `manipulation_verified=true`, `success=false`)로 뒷받침됩니다.
