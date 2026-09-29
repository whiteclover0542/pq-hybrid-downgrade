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

## 재현 ZIP

```bash
cd tools
python make_repro_package.py --package v1.1
python make_repro_package.py --package v1.2
python make_repro_package.py --package v1.3
```

[확실] 각각 `verify: ok=True missing=[]`가 출력되어야 합니다. v1.1 ZIP은 90회 원시 결과, v1.2 ZIP은 60회 핵심 표본, v1.3 ZIP은 120회 인과 분리 표본만 포함하며, 진단·부분 실행·v1.2 S4는 제외합니다.

[불확실] 이 패키지와 실험 결과를 다른 OpenSSL 배포·구성 또는 실배포 공격 가능성으로 일반화할 수 없습니다.
