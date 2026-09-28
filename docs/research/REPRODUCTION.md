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

[확실] `silent-downgrade`는 하네스 식별자이며, OpenSSL과 BoringSSL에서 하이브리드 광고, 고전-first `key_share`, 고전 `X25519` 협상, 성공, HRR 0회, 자동 flag 0회를 뜻합니다. OpenSSL의 v1.1 서버 설정은 명시적 single tuple `X25519MLKEM768:X25519`이므로 이 수락은 문서화된 tuple 선택 규칙과 일치합니다. 이 조건은 `DEFAULT`를 포함한 CVE-2026-2673 경로, 수정 버전 대조, RFC 비준수를 판정하지 않습니다.

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

## 7. v1.2 재현 (OpenSSL `DEFAULT` tuple-loss와 HRR 대조)

[확실] v1.2 최종 데이터는 `docs/research/baselines/raw/v1.2/`(JSON 60건, PCAP·client/server/capture 로그 각 60개)입니다. `docs/research/baselines/raw/v1.2-s4/`(S4 sanity control 20회)와 `/tmp/v12-smoke`는 결론 표본에서 제외합니다.

[확실] 이 절의 모든 명령은 WSL(Ubuntu) 안에서 실행합니다. Windows에서는 PowerShell로 `wsl -d Ubuntu -u root -- bash -lc '...'` 형태로 호출하며, 경로는 `/mnt/d/...`처럼 WSL 마운트 경로를 사용합니다(저장소의 Windows 경로 `D:\...`를 그대로 쓰지 않습니다).

### 7.1 A-0 환경 확인

[확실] 전제 조건: WSL Ubuntu, root 권한, python3, tshark, git.

[확실] 3.5.5 준비: 클라이언트와 3.5.5 서버 후보는 기존 설치 `/root/pq-hybrid-phase2/install/openssl`을 그대로 재사용합니다. 이 바이너리의 소스 트리는 `/root/pq-hybrid-phase2/openssl`(git commit `67b5686b4419b4cb8caa502711c41815f5279751`, tag `openssl-3.5.5`)입니다. 이 설치를 처음부터 다시 만들어야 한다면 다음을 실행합니다(정확한 configure 옵션은 `docs/research/v1.2-a0-environment.md` §7.1과 `docs/research/phase-2-environment.md`:26에서 그대로 옮긴 것이며, 재현 시에는 이 문서 텍스트를 신뢰하지 말고 그 두 원본을 다시 확인하십시오):

```bash
./Configure linux-x86_64 --prefix=/root/pq-hybrid-phase2/install/openssl --openssldir=/root/pq-hybrid-phase2/install/openssl/ssl no-tests
make -j2 install_sw
```

[확실] 서버 인증서 `apps/server.pem`은 이 소스 트리(`/root/pq-hybrid-phase2/openssl/apps/server.pem`)에서 옵니다. 3.5.6 빌드는 아래 `tools/v12_build_openssl_356.sh`로 수행합니다.

[확실] 두 서버 후보 각각에 대해 native-only smoke 스크립트를 실행합니다(클라이언트는 항상 3.5.5 고정).

```bash
wsl -d Ubuntu -u root -- bash /mnt/d/IT/git/PERSONAL/pq-hybrid-downgrade/pq-hybrid-downgrade/tools/v12_a0_smoke.sh /root/pq-hybrid-phase2/install/openssl
wsl -d Ubuntu -u root -- bash /mnt/d/IT/git/PERSONAL/pq-hybrid-downgrade/pq-hybrid-downgrade/tools/v12_a0_smoke.sh /root/pq-hybrid-phase2/install/openssl-3.5.6
```

[확실] 3.5.6이 아직 빌드되지 않았다면 먼저 빌드합니다. 이 스크립트는 기존 3.5.5 작업 트리에서 `openssl-3.5.6` 태그를 별도 git worktree로 분리하고, 수정 커밋 `85977e0`이 그 조상인지 확인한 뒤 별도 prefix로 빌드합니다.

```bash
wsl -d Ubuntu -u root -- bash /mnt/d/IT/git/PERSONAL/pq-hybrid-downgrade/pq-hybrid-downgrade/tools/v12_build_openssl_356.sh
```

[확실] 기대 출력에는 `fix-ancestor=yes`와 두 바이너리의 SHA-256이 포함됩니다(`docs/research/v1.2-a0-environment.md` §3 참고). BoringSSL의 tuple/HRR 설정 수단 조사는 `tools/v12_boringssl_survey.sh`로 재확인할 수 있습니다.

### 7.2 60회 실행과 분석

[확실] 보존된 `docs/research/baselines/raw/v1.2/`는 이미 60개 JSON을 담고 있으므로, `run_v12`는 이 디렉터리가 비어 있지 않으면 실행을 거부합니다(`RuntimeError: ... is not empty; choose a fresh --output-dir`). committed 데이터를 덮어쓰지 않고 새로 60회를 실행하려면 `--output-dir`로 별도 경로를 지정합니다.

```bash
wsl -d Ubuntu -u root -- bash -lc 'cd /mnt/d/IT/git/PERSONAL/pq-hybrid-downgrade/pq-hybrid-downgrade/tools && python3 -m faultinject.v12 --repeat 10 --output-dir /tmp/v12-rerun'
```

```bash
cd tools
python -m pytest -q
python3 -m faultinject.analyze --v12 --run-dir /tmp/v12-rerun
```

[확실] `cd tools && python -m pytest -q`는 v1.2 재현 ZIP(`tools/faultinject/tests/*.py`를 포함, §7.3)을 풀어 그 안에서 실행해도 대부분의 테스트가 통과하지만, 일부 테스트(`test_pcap_hello.py`, `test_v12_run.py`, `test_record_v12.py` 등)는 `docs/research/baselines/raw/v1.1/`의 fixture 파일을 읽습니다. v1.2 ZIP은 `raw/v1.1/`을 의도적으로 제외하므로(§7.3), 이 fixture들이 없으면 해당 테스트가 실패합니다. 전체 스위트를 통과시키려면 저장소 체크아웃에서(즉 `raw/v1.1/`이 함께 있는 위치에서) 실행하십시오; ZIP만 풀었다면 이 v1.1 의존 테스트들의 실패를 예상해야 합니다.

[확실] `python3 -m faultinject.analyze --v12`를 인자 없이 실행하면(`--run-dir` 생략) committed `docs/research/baselines/raw/v1.2/`를 읽어 이미 보존된 판정을 다시 도출합니다 — 새 실행 없이도 이 명령만으로 검증할 수 있습니다.

```bash
cd tools
python3 -m faultinject.analyze --v12
```

[확실] 위 `analyze --v12` 출력은 S1/S2/S3 × 3.5.5/3.5.6 6개 행과 `CVE-2026-2673 verdict: reproduced`를 보여야 합니다(정확한 수치는 `docs/research/v1.2-analysis.md` §3 참고). `analyze.py`에는 `--settings` 옵션이 없습니다 — S4 보조표를 별도로 확인하려면 `--run-dir`로 S4 전용 디렉터리를 직접 가리킵니다: `python3 -m faultinject.analyze --v12 --run-dir ../docs/research/baselines/raw/v1.2-s4`.

[확실] cp949 콘솔(Windows PowerShell 기본 코드페이지)에서 위 `analyze` 명령을 실행하면 판정 줄의 em-dash(`—`) 때문에 `UnicodeEncodeError`가 날 수 있습니다. `PYTHONIOENCODING=utf-8 python3 -m faultinject.analyze --v12`처럼 환경 변수를 지정하십시오.

### 7.3 v1.2 재현 ZIP

```bash
cd tools
python make_repro_package.py --package v1.2
```

[확실] `verify: ok=True missing=[]`가 출력되어야 합니다. v1.2 ZIP은 최종 `raw/v1.2/` 데이터(JSON 60·PCAP 60·client/server/capture 로그 각 60), `tools/faultinject` 소스, 논문, v1.2 설계, A-0 환경 대장, 결과 분석, 규범 분석, v1.1 감사 재계산 문서, A-0/3.5.6 빌드/BoringSSL 조사 스크립트, 이 재현 안내서를 포함하며 `v1.2-s4`와 `v1.1` 원시 데이터는 제외합니다.

[불확실] 이 패키지만으로 RFC 적합성, 실배포 공격 가능성, 모든 OpenSSL 배포·구성에서의 영향을 판정할 수 없습니다. S1의 HRR 부재는 CVE 증거로 사용하지 않습니다.
