# Phase 4 실행 설계

## 목적과 경계

- [확실] Phase 3 재현성 평가의 결과를 바탕으로 Phase 4에서 반복 실행 배치를 정의합니다.
- [확실] Phase 2·3 고정 인프라(바이너리·환경·감사 경로)를 그대로 사용합니다.
- [확실] 외부 호스트·실네트워크·미승인 대상에는 연결하거나 조작하지 않습니다.

## 표본 크기

- **기본 배치**: `--repeat 10` → 6조합 × 10회 = **60 실행**
  - 각 (impl, fault_type) 조합마다 정확히 10회 반복
- [확실] 검증 실패 시(예: 조작 미적용), 추가 배치로 보충하여 조합당 최소 10회 검증 성공 확보

## 실험 변인과 고정 요소

| 구분 | 설정 |
| --- | --- |
| **변인** |  |
| 구현체 | OpenSSL, BoringSSL, OpenSSH (3) |
| 결함 유형 | `group-list`, `binding` (2) |
| 조합 개수 | 3 × 2 = **6** |
| **고정 요소** |  |
| 조건 | `default` |
| 네트워크 | WSL2 loopback `127.0.0.1` |
| 하이브리드 그룹 설정 | Phase 2·3과 동일 |
| 로그·pcap 감사 경로 | Phase 2·3과 동일 |
| Phase 2 경로 | `/root/pq-hybrid-phase2/` |

## 파일명 규칙 및 출력 경로

### 실행 ID 형식

```
<impl>_<fault_type>_r<NN>_<condition>
```

**예시**:
- `openssl_group-list_r01_default`
- `boringssl_binding_r10_default`
- `openssh_group-list_r05_default`

### 원시 데이터 디렉토리

```
docs/research/baselines/raw/phase-4/
```

각 실행마다 다음 파일들이 생성됩니다:
- `<실행ID>-client.log`: 클라이언트 출력
- `<실행ID>-server.log`: 서버 출력
- `<실행ID>.pcapng`: 네트워크 트래픽(TLS 구현만)
- `<실행ID>-capture.log`: 캡처 상태
- `<실행ID>-proxy.log`: MITM 프록시 로그(binding 실패만)
- `<실행ID>.json`: 메트릭·검증 결과 레코드

## 재현 절차

### (1) 프리플라이트 (로컬 테스트)

```bash
cd tools
python -m pytest faultinject/tests/test_batch.py -v
python -m pytest -q
```

확인사항:
- 기본 단위 테스트 전부 통과
- 조합당 반복 수 정확성
- 6가지 조합 커버리지

### (2) Phase 4 배치 실행

```bash
cd tools
python -m faultinject.run --repeat 10
```

출력:
- 각 실행마다 한 줄: `<run_id>: result=<success|failure> verified=<true|false>`
- 모든 레코드는 `docs/research/baselines/raw/phase-4/`에 저장

### (3) 데이터 집계 및 분석

```bash
cd tools
python -m faultinject.aggregate
```

출력:
- `phase-4-analysis.md`: 전체 요약
- `phase-4-per-impl.csv`: 구현체별 통계
- 조작 검증 실패 목록 및 재배치 안내

## 기준 협상값

| 구현체 | 정상 하이브리드 협상값 |
| --- | --- |
| OpenSSL | `X25519MLKEM768` |
| BoringSSL | `X25519Kyber768Draft00` |
| OpenSSH | `sntrup761x25519-sha512@openssh.com` |

## 결함 주입 정의

| 결함 | 개입 지점 | 의미 | 조작 대상 |
| --- | --- | --- | --- |
| `group-list` | 클라이언트 CLI 옵션 | 하이브리드 그룹을 제외한 제안 발송 | 인자 목록 |
| `binding` | loopback MITM 프록시 | 하이브리드 교환의 PQ 성분 위조 | key_share/KEX_ECDH_INIT |

## 실행 기록 (실제 실행)

- [확실] **실행 일시**: 2026-09-23 06:13:17 ~ 06:16:50 KST (약 3분 33초), WSL2 Ubuntu, `tools/` 디렉토리에서 `python3 -m faultinject.run --repeat 10` 1회 실행
- [확실] **프리플라이트**: `preflight(phase2_paths(), phase2_environment())` → `(True, 'ok')` 확인 후 배치 시작
- [확실] **총 실행 수**: 60건 (6조합 × 10회), 추가 보충 배치 없이 1차 배치만으로 전 조합 표본 크기 충족
- [확실] **조합별 검증 결과** (`python3 -m faultinject.aggregate` 출력, `manifest.csv` 기준):

| implementation | fault_type | total | verified | success | downgrade |
| --- | --- | --- | --- | --- | --- |
| boringssl | binding | 10 | 10 | 0 | 0 |
| boringssl | group-list | 10 | 10 | 10 | 10 |
| openssh | binding | 10 | 10 | 0 | 0 |
| openssh | group-list | 10 | 10 | 10 | 10 |
| openssl | binding | 10 | 10 | 0 | 0 |
| openssl | group-list | 10 | 10 | 10 | 10 |

- [확실] 6조합 모두 `verified=10 (≥10)`으로 표본 크기 기준 충족 — `aggregate` 출력 마지막 줄 `sample size OK`.
- [확실] **결과 해석 (데이터이지 오류가 아님)**: `binding` 조합(3구현체 모두)은 `success=0`으로, 즉 MITM 프록시가 PQ 성분을 위조한 핸드셰이크가 전부 실패(거부)했습니다. 이는 하이브리드 바인딩이 조작을 탐지·거부했다는 측정 결과이며, 실행 실패가 아닙니다. `group-list` 조합(3구현체 모두)은 `success=10, downgrade=10`으로, 하이브리드 그룹을 제외한 제안이 전부 성공적으로 다운그레이드되었습니다.
- [확실] **원시 데이터 보존**: 기존에 존재하던 raw 파일은 없었으며(최초 배치), 이번 실행으로 생성된 60건 × 6파일(json/client.log/server.log/pcapng/capture.log, binding 조합은 proxy.log 추가) + `manifest.csv` 1건을 그대로 유지했습니다. 어떤 기존 원시 데이터도 삭제·수정하지 않았습니다.

## 설계 변경 로그

| 날짜 | 변경 사항 |
| --- | --- |
| 2026-09-23 | 변경 없음 — 실행 시작 시점 설계 그대로 |
| 2026-09-23 (실행 후) | 변경 없음 — 배치 실행·집계 중 `tools/faultinject/` 코드나 설계 변수를 수정하지 않음. 1차 배치(60건)만으로 6조합 전부 `verified≥10` 충족하여 보충 배치도 불필요했음 |
