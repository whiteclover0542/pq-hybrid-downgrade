# 재현 안내

[확실] 이 문서는 명령만 제공합니다. 표본·환경·판정·한계는 [근거 대장](../EVIDENCE.md), 결론은 [논문](../PAPER.md)을 보십시오.

## 보존 데이터 검증

[확실] 보존된 `raw/v1.1/`과 `raw/v1.2/`에는 쓰지 마십시오. 새 실행은 반드시 새 `--output-dir`에 저장합니다.

```bash
cd tools
python -m pytest -q
python -m faultinject.aggregate --v11 --run-dir ../docs/research/baselines/raw/v1.1
python -m faultinject.analyze --v11 --run-dir ../docs/research/baselines/raw/v1.1
python -m faultinject.analyze --v12
```

[확실] v1.1은 9개 조합마다 r01–r10, 총 JSON 90개와 `verified=10`을 보여야 합니다. v1.2는 S1–S3 × 3.5.5/3.5.6의 6행과 `CVE-2026-2673 verdict: reproduced`를 출력해야 합니다.

## v1.1 새 실행

[확실] WSL에서 잔류 `faultinject`, `openssl`, `bssl`, `sshd`, `tshark`, proxy 프로세스와 테스트 포트를 점검한 뒤, stdout·stderr를 보존할 수 있는 분리된 터미널에서 실행하십시오.

```bash
cd tools
python -m faultinject.run --v11 10 --output-dir /absolute/path/to/fresh-v11-run
python -m faultinject.aggregate --v11 --run-dir /absolute/path/to/fresh-v11-run
python -m faultinject.analyze --v11 --run-dir /absolute/path/to/fresh-v11-run
```

[확실] `v1.1-diagnose*`, `v1.1-pre-*`, `v1.1-preflight-*`는 최종 데이터가 아니며 검토·패키지에서 제외합니다.

## v1.2 새 실행

[확실] WSL Ubuntu에서 3.5.5 클라이언트를 고정하고, 3.5.6 서버를 별도 prefix에 준비합니다. 아래 스크립트가 default-provider 환경과 수정 커밋 조상을 확인합니다.

```bash
wsl -d Ubuntu -u root -- bash /mnt/d/IT/git/PERSONAL/pq-hybrid-downgrade/pq-hybrid-downgrade/tools/v12_build_openssl_356.sh
wsl -d Ubuntu -u root -- bash /mnt/d/IT/git/PERSONAL/pq-hybrid-downgrade/pq-hybrid-downgrade/tools/v12_a0_smoke.sh /root/pq-hybrid-phase2/install/openssl
wsl -d Ubuntu -u root -- bash /mnt/d/IT/git/PERSONAL/pq-hybrid-downgrade/pq-hybrid-downgrade/tools/v12_a0_smoke.sh /root/pq-hybrid-phase2/install/openssl-3.5.6
```

```bash
wsl -d Ubuntu -u root -- bash -lc 'cd /mnt/d/IT/git/PERSONAL/pq-hybrid-downgrade/pq-hybrid-downgrade/tools && python3 -m faultinject.v12 --repeat 10 --output-dir /tmp/v12-rerun'
cd tools
python3 -m faultinject.analyze --v12 --run-dir /tmp/v12-rerun
```

[확실] `raw/v1.2/`가 비어 있지 않으면 실행기는 덮어쓰기를 거부합니다. S4는 결론 표본이 아니므로, 필요하면 별도 출력 경로에서만 실행하십시오.

## v1.3 인과 분리 새 실행

[확실] 수정 커밋 `85977e0`의 `ssl/t1_lib.c` 변경만 3.5.5에 적용한 서버, 3.5.6에서 되돌린 서버, 3.6.1과 3.6.2를 각각 별도 prefix에 빌드합니다. 스크립트는 태그 commit, 수정 커밋 조상 여부, 적용한 patch의 SHA-256, 설치된 바이너리 해시와 `openssl version`을 출력합니다. 기존 3.5.5·3.5.6 설치는 변경하지 않습니다.

```bash
wsl -d Ubuntu -u root -- bash /mnt/d/IT/git/PERSONAL/pq-hybrid-downgrade/pq-hybrid-downgrade/tools/v13_build_variants.sh
```

```bash
wsl -d Ubuntu -u root -- bash -lc 'cd /mnt/d/IT/git/PERSONAL/pq-hybrid-downgrade/pq-hybrid-downgrade/tools && python3 -m faultinject.v12 --repeat 10 --versions 3.5.5-cherrypick,3.5.6-revert,3.6.1,3.6.2 --output-dir /tmp/v13-rerun'
cd tools
python3 -m faultinject.analyze --v13 --run-dir /tmp/v13-rerun
```

[확실] 보존된 120회 결과는 `python -m faultinject.analyze --v13`으로 다시 집계하며, 마지막 줄이 `Causal-isolation verdict: consistent`여야 합니다. 패치 변형은 `openssl` CLI 바이너리가 원본과 같으므로, 서버 구분은 기록의 `provenance.server_libssl_sha256`으로 확인합니다.

## v1.4 하이브리드 우선 클라이언트 새 실행

[확실] v1.2와 같은 서버·설정에서 클라이언트만 하이브리드를 1순위로 광고하고 `X25519` key share만 보내도록 바꿉니다.

```bash
wsl -d Ubuntu -u root -- bash -lc 'cd /mnt/d/IT/git/PERSONAL/pq-hybrid-downgrade/pq-hybrid-downgrade/tools && python3 -m faultinject.v12 --repeat 10 --client-groups "X25519MLKEM768:*X25519" --output-dir /tmp/v14-rerun'
cd tools
python3 -m faultinject.analyze --v12 --run-dir /tmp/v14-rerun
```

[확실] 보존된 60회 결과는 `python -m faultinject.analyze --v12 --run-dir ../docs/research/baselines/raw/v1.4`로 다시 집계합니다.

## v1.5 다섯 TLS 구현의 협상 함수 비교

[확실] Go·rustls 최소 서버를 빌드하고(Go는 WSL에 설치된 것을 쓰고, Rust는 없으면 rustup으로 설치), NSS 인증서 DB를 만든 뒤 105회를 실행합니다. 빌드 산출물은 저장소 밖 `/root/pq-hybrid-phase2/v15/`에 둡니다.

```bash
wsl -d Ubuntu -u root -- bash /mnt/d/IT/git/PERSONAL/pq-hybrid-downgrade/pq-hybrid-downgrade/tools/v15_setup.sh
wsl -d Ubuntu -u root -- bash -lc 'cd /mnt/d/IT/git/PERSONAL/pq-hybrid-downgrade/pq-hybrid-downgrade/tools && python3 -m faultinject.v15 --repeat 5 --output-dir /tmp/v15-rerun'
cd tools
python3 -m faultinject.v15 --report /tmp/v15-rerun
```

[확실] 보존된 105회는 `python -m faultinject.v15 --report ../docs/research/baselines/raw/v1.5`로 다시 집계합니다. 최신 BoringSSL 대조 9회는 `python -m faultinject.v15 --report ../docs/research/baselines/raw/v1.5-boringssl-latest`로 집계하고, 재실행은 `tools/v15_build_boringssl_latest.sh`와 `tools/v15_run_boringssl_latest.sh`를 사용합니다. 8545 포트가 막 해제된 직후에는 사전 점검이 실행을 거부할 수 있으니 잠시 뒤 다시 실행합니다.

## v1.6 클라이언트 기본값 조사와 실제 서버 소프트웨어

[확실] v1.5 준비가 끝난 상태에서 nginx·Caddy 패키지를 설치하고 Go·rustls 기본 클라이언트를 빌드한 뒤 36회를 실행합니다. nginx와 Caddy 설정은 수신 포트·인증서(nginx는 프로토콜도)만 지정하고 그룹 설정은 두지 않습니다.

```bash
wsl -d Ubuntu -u root -- bash /mnt/d/IT/git/PERSONAL/pq-hybrid-downgrade/pq-hybrid-downgrade/tools/v16_setup.sh
wsl -d Ubuntu -u root -- bash -lc 'cd /mnt/d/IT/git/PERSONAL/pq-hybrid-downgrade/pq-hybrid-downgrade/tools && python3 -m faultinject.v16 --repeat 3 --output-dir /tmp/v16-rerun'
cd tools
python3 -m faultinject.v16 --report /tmp/v16-rerun
```

[확실] 보존된 36회는 `python -m faultinject.v16 --report ../docs/research/baselines/raw/v1.6`로 다시 집계합니다. 기본값 조사 기록의 `handshake_result`는 OpenSSL 외 클라이언트의 출력 형식을 판정하지 않으므로 `failure`로 남으며, 조사는 ClientHello와 서버가 고른 그룹만 봅니다.

[확실] 기본 클라이언트·기본 서버 직접 연결 36회는 `python -m faultinject.v16 --report ../docs/research/baselines/raw/v1.6-direct`로 집계하고, 재실행은 `tools/v16_run_direct_defaults.sh`를 사용합니다. `v1.6-caddy-2.11.4`는 v1.6 재실행 36회이며 그중 Caddy 2.11.4의 C1–C3 대조는 9회입니다. 이 디렉터리는 `python -m faultinject.v16 --report ../docs/research/baselines/raw/v1.6-caddy-2.11.4`로 집계하고, 재실행은 `tools/v16_run_caddy_2114.sh`를 사용합니다. 기본 클라이언트를 Caddy 2.11.4에 직접 연결한 표본은 없습니다. 두 Caddy 바이너리의 원시 build 정보와 Ubuntu NSS 패치 목록은 각각 해당 raw 디렉터리와 `nss-ubuntu-patches-20260929.log`에 보존합니다.

## v1.7 브라우저 조사, 상세 감사 출력, OpenSSL 3.6 인과 분리

[확실] 3.6 변형 두 개를 빌드하고 60회를 실행합니다.

```bash
wsl -d Ubuntu -u root -- bash /mnt/d/IT/git/PERSONAL/pq-hybrid-downgrade/pq-hybrid-downgrade/tools/v13_build_variants.sh 3.6.1-cherrypick 3.6.2-revert
wsl -d Ubuntu -u root -- bash -lc 'cd /mnt/d/IT/git/PERSONAL/pq-hybrid-downgrade/pq-hybrid-downgrade/tools && python3 -m faultinject.v12 --repeat 10 --versions 3.6.1-cherrypick,3.6.2-revert --output-dir /tmp/v17-openssl36'
cd tools
python3 -m faultinject.analyze --v17 --run-dir /tmp/v17-openssl36
```

[확실] v1.6 준비가 끝난 상태에서 headless Chrome·Firefox를 설치하고 브라우저 6회와 `s_client -trace` 9회를 실행한 뒤, 보존 PCAP에 `tshark -V`를 적용합니다.

```bash
wsl -d Ubuntu -u root -- bash /mnt/d/IT/git/PERSONAL/pq-hybrid-downgrade/pq-hybrid-downgrade/tools/v17_setup.sh
wsl -d Ubuntu -u root -- bash -lc 'cd /mnt/d/IT/git/PERSONAL/pq-hybrid-downgrade/pq-hybrid-downgrade/tools && python3 -m faultinject.v17 --repeat 3 --output-dir /tmp/v17-rerun'
wsl -d Ubuntu -u root -- bash -lc 'cd /mnt/d/IT/git/PERSONAL/pq-hybrid-downgrade/pq-hybrid-downgrade/tools && R=../docs/research/baselines/raw && python3 -m faultinject.v17 --verbose-pass $R/v1.2 $R/v1.3 $R/v1.4 $R/v1.5 $R/v1.5-boringssl-latest $R/v1.6 $R/v1.6-direct $R/v1.6-caddy-2.11.4 $R/v1.7-openssl36 $R/v1.7 --verbose-json /tmp/v17-verbose.json'
```

[확실] 보존된 결과는 `python -m faultinject.analyze --v17`(3.6 인과 분리)과 `python -m faultinject.v17 --report ../docs/research/baselines/raw/v1.7 --verbose-json ../docs/research/baselines/raw/v1.7-tshark-verbose-audit.json`(브라우저, `-trace`, `tshark -V`)으로 다시 집계합니다. `--verbose-pass`는 `tshark`가 있는 WSL에서 실행합니다.

## 재현 ZIP

```bash
cd tools
python make_repro_package.py --package v1.1
python make_repro_package.py --package v1.2
python make_repro_package.py --package v1.3
python make_repro_package.py --package v1.4
python make_repro_package.py --package v1.5
python make_repro_package.py --package v1.6
python make_repro_package.py --package v1.7
```

[확실] 각각 `verify: ok=True missing=[]`가 출력되어야 합니다. v1.1 ZIP은 90회 원시 결과, v1.2 ZIP은 60회 핵심 표본, v1.3 ZIP은 120회 인과 분리 표본, v1.4 ZIP은 60회 하이브리드 우선 클라이언트 표본, v1.5 ZIP은 105회 협상 함수 비교 표본을 포함합니다. v1.6 ZIP은 기존 36회 기본값 조사에 최신 BoringSSL 9회, 기본 직접 연결 36회, v1.6 재실행 36회(Caddy 2.11.4 9회 포함)와 Caddy·NSS 원시 환경 기록을 더해 검증합니다. v1.7 ZIP은 브라우저·`-trace` 15회, 3.6 인과 분리 60회, `tshark -V` 재측정 결과를 포함합니다. 진단·부분 실행·v1.2 S4는 제외합니다.

[불확실] 이 패키지와 실험 결과를 다른 OpenSSL 배포·구성 또는 실배포 공격 가능성으로 일반화할 수 없습니다.
