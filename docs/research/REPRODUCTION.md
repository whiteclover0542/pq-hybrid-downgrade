# 재현 절차 (Reproduction Guide)

이 문서는 제3자가 Phase 4 결함 주입 실험(6조합 × 10회 = 60 실행)을 처음부터 재현하기 위한 단계별 절차입니다. `dist/pq-hybrid-downgrade-repro.zip`에 이 문서와 함께 원시 데이터·실행 코드가 번들로 포함되어 있습니다.

## 1. 전제 조건

- [확실] **OS**: WSL2 위의 Ubuntu (본 연구는 Ubuntu 26.04.1 LTS, 커널 `6.6.87.2-microsoft-standard-WSL2`, x86_64에서 실행했습니다). 네이티브 Linux에서도 동일하게 동작해야 합니다.
- [확실] **Python**: 3.11 이상 (표준 라이브러리만 사용, 추가 pip 패키지 불필요).
- [확실] **Phase 2 빌드 바이너리**: OpenSSL(+oqsprovider), BoringSSL, OpenSSH의 PQ 하이브리드 빌드가 필요합니다. 본 연구에서는 `/root/pq-hybrid-phase2/`에 설치했습니다 (`docs/research/phase-2-environment.md` 참고). **이 절대 경로는 실행 환경마다 다를 수 있으므로 사용자 환경에 맞게 바꿀 것.** `tools/faultinject/run.py`의 `PHASE2_ROOT` 상수를 자신의 설치 경로로 수정하십시오.
  - 필요한 바이너리: `install/openssl/bin/openssl`, `build/boringssl/tool/bssl`, `openssh/ssh`, `openssh/sshd` 및 관련 인증서·설정 파일. 정확한 하위 경로는 `tools/faultinject/run.py`의 `phase2_paths()` 함수를 참고하십시오.
- [확실] **tshark**: loopback 패킷 캡처(`.pcapng`)에 필요합니다 (TLS 구현체만 해당, OpenSSH는 미사용).
- [확실] 모든 handshake는 `127.0.0.1` loopback에서만 수행되며, 외부 호스트·실네트워크에는 연결하지 않습니다.

## 2. 프리플라이트 (로컬 테스트)

레포 루트에서:

```bash
cd tools
python -m pytest faultinject/tests/test_batch.py -v
python -m pytest -q
```

확인 사항:
- 단위 테스트 전부 통과 (tshark 미설치 환경에서는 관련 1개 테스트가 SKIP될 수 있으며 정상입니다)
- 6가지 조합(구현체 3 × 결함 유형 2) 커버리지 및 조합당 반복 수 계산 로직 검증

`run.py`의 `preflight()`가 실제 배치 실행 전 바이너리 존재 여부와 `oqsprovider` 로드 여부를 자동으로 점검하므로, 위 테스트가 통과한 뒤 Phase 2 경로가 올바르게 설정되어 있는지 다시 한번 확인하십시오.

## 3. Phase 4 배치 실행

```bash
cd tools
python -m faultinject.run --repeat 10
```

- [확실] 각 (구현체, 결함 유형) 조합마다 정확히 10회씩 반복 실행하여 총 6 × 10 = **60회** 실행합니다.
- 실행마다 표준 출력에 한 줄씩 출력됩니다: `<run_id>: result=<success|failure> verified=<true|false>`
- 프리플라이트(`preflight()`)가 실패하면(바이너리 누락 등) 배치를 시작하지 않고 오류 메시지를 출력한 뒤 종료 코드 1을 반환합니다.
- 모든 레코드(원시 로그·pcap·JSON)는 `docs/research/baselines/raw/phase-4/`에 저장됩니다.

## 4. 데이터 집계

```bash
cd tools
python -m faultinject.aggregate
```

- [확실] `docs/research/baselines/raw/phase-4/manifest.csv`를 생성합니다. 열: `implementation, fault_type, total, verified, success, downgrade`.
- 표준 출력에 조합별 통계와 최종 판정(`sample size OK` 또는 `sample size NOT met (need >=10 verified per combo)`)을 출력합니다.
- 조합이 6개 미만이거나 어느 조합이든 `verified < 10`이면 판정은 실패(NOT met)이며, 이 경우 `python -m faultinject.run --repeat N`으로 보충 배치를 추가 실행해 부족한 조합을 채우십시오 (기존 원시 데이터는 삭제되지 않고 누적됩니다).

## 5. 기대 결과

- [확실] 6조합(구현체 `openssl`/`boringssl`/`openssh` × 결함 유형 `group-list`/`binding`) 모두 `verified=10` (표본 크기 기준 `verified >= 10` 충족), 최종 줄 `sample size OK`.
- [확실] `binding` 조합 3개는 `success=0`이 기대값입니다 — MITM 프록시가 PQ 성분을 위조한 핸드셰이크는 전부 거부되어야 정상이며, 이는 하이브리드 바인딩이 조작을 탐지했다는 측정 결과이지 실행 오류가 아닙니다.
- [확실] `group-list` 조합 3개는 `success=10, downgrade=10`이 기대값입니다 — 하이브리드 그룹을 제외한 제안이 전부 성공적으로 다운그레이드됩니다.
- 실제 실행 기록과 결과표는 `docs/research/phase-4-execution.md`의 "실행 기록 (실제 실행)" 절을 참고하십시오.

## 6. 산출물 위치

| 산출물 | 경로 |
| --- | --- |
| 원시 실행 레코드(json/log/pcapng) | `docs/research/baselines/raw/phase-4/` |
| 집계 매니페스트 | `docs/research/baselines/raw/phase-4/manifest.csv` |
| 결함 주입 실행 코드 | `tools/faultinject/` |
| 본 재현 절차 문서 | `docs/research/REPRODUCTION.md` |
| Phase 4 실행 설계·실행 기록 | `docs/research/phase-4-execution.md` |
| 단일 ZIP 재현 패키지 | `dist/pq-hybrid-downgrade-repro.zip` (`tools/make_repro_package.py`로 생성) |

## 7. 재현 패키지 검증

배포된 ZIP(`dist/pq-hybrid-downgrade-repro.zip`)은 어느 위치에 풀어도 동작하도록 상대 경로로만 저장되어 있습니다. 무결성을 확인하려면:

```bash
cd tools
python -c "from make_repro_package import verify_zip; print(verify_zip('../dist/pq-hybrid-downgrade-repro.zip'))"
```

`(True, [])`가 출력되면 필수 파일(매니페스트, 실행 코드, 원시 phase-4 JSON 60건 이상, 본 문서)이 모두 포함된 것입니다.
