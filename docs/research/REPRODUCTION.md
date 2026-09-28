# v1.1 재현 안내서

## 1. 범위와 보존 원칙

[확실] 이 안내서는 v1.1 P2/P3의 최종 데이터셋을 검토하고, 필요하면 새 출력 경로에서 별도 반복 실험을 실행하는 절차입니다. 최종 데이터는 `docs/research/baselines/raw/v1.1/`이며 JSON 90건, PCAP 90개, client log 90개, capture log 90개, on-path proxy log 30개를 포함합니다.

[확실] `v1.1-pre-p2-*`, `v1.1-preflight-*`, `v1.1-diagnose*`는 최종 결과가 아닙니다. 검토·집계·ZIP 검증에서 제외해야 하며, 삭제하거나 최종 `v1.1/`과 섞으면 안 됩니다.

[확실] 보존된 최종 `raw/v1.1/`에 대해 `python -m faultinject.run --v11 10`을 실행하지 마십시오. 기본 경로가 기존 JSON과 proxy log를 덮어쓰거나 누적할 수 있습니다.

## 2. 검토용 준비

[확실] 패키지 또는 저장소 루트에서 다음 명령을 실행합니다.

```bash
cd tools
python -m pytest -q
python -m faultinject.aggregate --v11 --run-dir ../docs/research/baselines/raw/v1.1
python -m faultinject.analyze --v11 --run-dir ../docs/research/baselines/raw/v1.1
```

[확실] 집계 명령은 파일을 만들거나 수정하지 않습니다. 9개 구현×조건 행마다 `total=10`, `verified=10`이 출력되어야 하며, 분석 표는 condition 축의 성공·실패·HRR·자동 flag 수를 보여 줍니다. 이 HRR 수는 수집 당시 JSON의 `hrr_present`이므로 OpenSSL `onpath-strip`에서도 0으로 출력되지만, PCAP 교차 검증 결과 이 조건에서는 10회 모두 HRR이 발생했습니다. 논문 표는 PCAP 값을 사용합니다(정정 근거: `docs/research/v1.1-p3-analysis.md`의 Correction 절).

## 3. 최종 데이터 무결성 점검

[확실] 각 행은 r01부터 r10까지 정확히 한 번 존재해야 합니다. 원시 결과의 기준표와 해석은 `docs/research/v1.1-p3-analysis.md`에 있고, 실행 보존·artifact 검증 근거는 `.planning/phases/07-v11-tooling/07-02-SUMMARY.md`에 있습니다.

[확실] `silent-downgrade`는 OpenSSL과 BoringSSL에서 하이브리드 광고, 고전 `X25519` 협상, 성공, HRR 0회, 자동 flag 0회를 뜻하는 조작적 조건입니다. 이는 CVE 재현이나 RFC 비준수 판정이 아닙니다.

## 4. 새 경로에서의 반복 실행

[확실] 새 실험에는 WSL2 Linux, Python 3.11 이상, 고정된 Phase 2 OpenSSL(+oqs-provider)·BoringSSL·OpenSSH 빌드와 TLS loopback capture용 tshark가 필요합니다. `tools/faultinject/run.py`의 `PHASE2_ROOT`를 해당 환경의 빌드 경로와 일치시켜야 합니다.

[확실] 먼저 WSL에서 이전 faultinject, openssl, bssl, sshd, tshark, proxy 프로세스와 테스트 포트 점유를 점검하고 종료 로그를 보존하십시오. 실행은 stdout·stderr를 별도 파일로 보존할 수 있는 안정적인 WSL 터미널 또는 분리 프로세스에서 수행합니다.

```bash
cd tools
python -m faultinject.run --v11 10 --output-dir /absolute/path/to/fresh-v11-run
python -m faultinject.aggregate --v11 --run-dir /absolute/path/to/fresh-v11-run
python -m faultinject.analyze --v11 --run-dir /absolute/path/to/fresh-v11-run
```

[확실] `--output-dir`는 v1.1 실행에서만 사용할 수 있으며, 새 디렉터리를 지정해 보존된 최종 데이터와 새 데이터를 분리합니다. 새 실행의 JSON·artifact 수와 조작 검증은 최종 데이터와 독립적으로 검토해야 합니다.

## 5. v1.1 재현 ZIP

[확실] v1.1 ZIP은 최종 `raw/v1.1/` 데이터와 artifact, `tools/faultinject` 소스, 논문, v1.1 설계, P2 요약, P3 분석, 이 안내서를 포함합니다. 진단·preflight·부분 실행 데이터는 포함하지 않습니다.

```bash
cd tools
python make_repro_package.py --out ../dist/pq-hybrid-downgrade-v11-repro.zip
python -c "from make_repro_package import verify_zip; print(verify_zip('../dist/pq-hybrid-downgrade-v11-repro.zip'))"
```

[확실] 검증 결과 `(True, [])`는 필수 문서와 최소 90 JSON·90 PCAP·90 client log·90 capture log·30 proxy log가 ZIP에 있음을 뜻합니다.

## 6. 해석 경계

[확실] 이 패키지는 시험한 그룹 순서와 감사 정의에서의 관측을 재현합니다. OpenSSH 경로상 결과는 실패한 구조적 대조군이며, 성공한 TLS 다운그레이드와 동등하지 않습니다.

[불확실] 이 패키지만으로 RFC 적합성, 실배포 공격 가능성, 취약점 영향 범위, CVE 동일성을 판정할 수 없습니다.
