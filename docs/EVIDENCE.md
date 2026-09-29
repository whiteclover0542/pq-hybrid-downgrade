# 연구 근거 대장

이 문서는 여러 단계별 설계·환경·분석·완료 기록을 하나로 합친 유일한 근거 대장입니다. 원시 데이터는 `docs/research/baselines/raw/`에 그대로 보존하며, 과거 작업 문서는 Git 이력에서만 확인합니다.

## 검증 범위

[확실] 주 결과는 v1.2의 OpenSSL `DEFAULT` tuple-loss 재현입니다. 고정 OpenSSL 3.5.5 native-only 클라이언트가 `X25519:X25519MLKEM768`을 광고하고 `X25519` key share만 전송한 상태에서, 서버 버전(3.5.5/3.5.6)과 group-list(S1/S2/S3)를 교차해 각 10회, 총 60회를 실행했습니다.

[확실] HRR의 주 판정은 PCAP 속 ServerHello random이 RFC 8446의 HelloRetryRequest 고정값 `cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c`와 일치하는지입니다. 클라이언트 `-msg` 로그는 보조 증거입니다.

[확실] 서버 설정은 S1 `X25519MLKEM768:X25519`(하나의 명시적 tuple), S2 `X25519MLKEM768/X25519`(명시적 tuple 경계), S3 `DEFAULT`입니다. `:`는 tuple 안의 그룹을, `/`는 tuple 경계를 뜻합니다. S4(설정 생략)는 20회 보조 표본으로만 보존하며 결론 표본에 포함하지 않습니다.

## 환경과 대조군

[확실] 클라이언트와 3.5.5 서버는 동일한 native-only OpenSSL 3.5.5 바이너리(SHA-256 `7b1a89948e5e2375ae24a47bd579bbd59c48e8f2fcef4508d6c5e943aba46ef1`)를 사용했습니다. 3.5.6 서버는 별도 prefix의 OpenSSL 3.5.6 바이너리(SHA-256 `88a896e54ede812cc7b944c307d4d159f478ac039f6dc08fa73da6d1cbe447eb`)입니다. 두 환경 모두 default provider만 사용하고 `X25519MLKEM768` 지원을 확인했습니다.

[확실] 3.5.6 소스는 `openssl-3.5.6` 태그(commit `286ddeaac037533bbdce65b3c689e3f7ffebf0f6`)이며, 수정 커밋 `85977e013f32ceb96aa034c0e741adddc1a05e34`가 조상임을 `git merge-base --is-ancestor`로 확인했습니다.

[확실] BoringSSL은 OpenSSL의 tuple 구문이나 `DEFAULT`에 대응하는 서버 설정 문법이 없어 v1.2의 CVE 핵심 표본에서 제외했습니다. 이는 BoringSSL이 안전하거나 동등하다는 판정이 아니라, 동등 조건을 설정할 수 없었다는 범위 제한입니다.

## v1.2 원시 결과

[확실] `docs/research/baselines/raw/v1.2/`에는 JSON 60개, PCAP 60개, client/server/capture log 각 60개가 있습니다. 다음 표는 `cd tools && python -m faultinject.analyze --v12`의 보존 결과입니다.

| 서버 | 설정 | 반복 | 성공 | HRR (PCAP) | hybrid | classical |
|---|---|---:|---:|---:|---:|---:|
| 3.5.5 | S1 | 10 | 10 | 0 | 0 | 10 |
| 3.5.5 | S2 | 10 | 10 | 10 | 10 | 0 |
| 3.5.5 | S3 `DEFAULT` | 10 | 10 | 0 | 0 | 10 |
| 3.5.6 | S1 | 10 | 10 | 0 | 0 | 10 |
| 3.5.6 | S2 | 10 | 10 | 10 | 10 | 0 |
| 3.5.6 | S3 `DEFAULT` | 10 | 10 | 10 | 10 | 0 |

[확실] S3만 두 버전에서 갈렸습니다. 3.5.5는 10/10에서 HRR 없이 `X25519`를 완료했고, 3.5.6은 10/10에서 PCAP HRR 후 `X25519MLKEM768`을 완료했습니다. S1과 S2는 두 버전에서 동일한 대조 결과를 보였습니다. 따라서 다음 네 판정 조건(3.5.5 S3 classical/no-HRR, 3.5.6 S3 hybrid/HRR, S1/S2 대조, 조합별 10회와 artifact 보존)을 충족해 이 고정 테스트베드에서 CVE-2026-2673 발현과 수정 대조가 재현됐다고 기록합니다.

[확실] S4(서버 설정 생략)는 두 버전 20/20에서 HRR 후 hybrid로 끝났습니다. `DEFAULT` 키워드 확장과 설정 생략은 같은 조건이 아니므로 이 값은 결론 판정에 쓰지 않습니다.

## v1.3 인과 분리

[확실] v1.2의 3.5.5→3.5.6 대조에는 수정 커밋 외 변경이 섞여 있으므로, `tools/v13_build_variants.sh`로 네 서버를 별도 prefix에 빌드해 같은 클라이언트·명령·S1–S3 행렬로 조합별 10회, 총 120회를 실행했습니다(`docs/research/baselines/raw/v1.3/`, 종료 코드 0, stderr 0바이트). 수정 커밋 `85977e0`이 바꾼 파일 중 라이브러리 코드는 `ssl/t1_lib.c` 하나이며 나머지는 문서와 테스트입니다.

| 서버 | 출처 | 수정 변경 | libssl.so.3 SHA-256 |
|---|---|---|---|
| 3.5.5-cherrypick | `openssl-3.5.5`(`67b5686b…`) + `85977e0`의 `ssl/t1_lib.c` 변경(patch SHA-256 `0a7e0206a9ca…`) | 있음 | `ef30c6d8de549ce28e5e757362c997b808f2c2c411996737d3a79c00b11012ab` |
| 3.5.6-revert | `openssl-3.5.6`(`286ddeaa…`) − 같은 변경(patch SHA-256 `0b7674abe147…`) | 없음 | `a9d8f36e38b258704e483a2872ab9de32ee4d0110aac098177cfc588f92c5279` |
| 3.6.1 | `openssl-3.6.1`(`c9a9e5b1…`), `2157c9d` 미포함 | 없음 | `fb70fdbf1a67de864a4f7b61829f30d86d558dbc023404affbee2b1cccdcad61` |
| 3.6.2 | `openssl-3.6.2`(`fe686e15…`), `2157c9d` 포함 | 있음 | `708d5e708526c65c1af8737d59e7ddf21d7d03276921944e1e9a1e0356e2c619` |

[확실] 기준 설치의 libssl은 3.5.5 `a785209382213c37…`, 3.5.6 `aff23fc605b58c6f…`로, 여섯 서버의 libssl 해시가 모두 다릅니다. 패치 변형의 `openssl` CLI 바이너리는 원본과 같으므로(3.5.5-cherrypick은 `7b1a89948e5e…`, 3.5.6-revert는 `88a896e54ede…`), 각 기록의 `provenance.server_libssl_sha256`으로 서버를 구분합니다. 클라이언트는 120회 모두 3.5.5 바이너리(`7b1a89948e5e…`)입니다.

| 서버 | S1 HRR / 그룹 | S2 HRR / 그룹 | S3 `DEFAULT` HRR / 그룹 |
|---|---|---|---|
| 3.5.5-cherrypick | 0/10 · X25519 | 10/10 · X25519MLKEM768 | 10/10 · X25519MLKEM768 |
| 3.5.6-revert | 0/10 · X25519 | 10/10 · X25519MLKEM768 | 0/10 · X25519 |
| 3.6.1 | 0/10 · X25519 | 10/10 · X25519MLKEM768 | 0/10 · X25519 |
| 3.6.2 | 0/10 · X25519 | 10/10 · X25519MLKEM768 | 10/10 · X25519MLKEM768 |

[확실] `cd tools && python -m faultinject.analyze --v13`의 판정은 `Causal-isolation verdict: consistent`입니다. 120건 모두 클라이언트 전제가 PCAP으로 검증됐고, 성공 120/120, HRR 로그·PCAP 판정 일치, 실제 ServerHello 1개였습니다. S3 결과는 `ssl/t1_lib.c`의 수정 변경 하나로 뒤집혔고, 3.5와 3.6 두 계열에서 같은 방향으로 갈렸습니다.

## 연구 질문에 대한 답

[추정] 착수 질문(`docs/PROPOSAL.md`: 협상 로직 결함에 의한 하이브리드 PQ 다운그레이드가 특정 라이브러리의 우연한 버그인가, 여러 구현체에 걸친 일반적 패턴인가)에 대해, 시험 범위의 답은 다음과 같습니다. 결함은 OpenSSL의 `DEFAULT` 확장 코드 경로에 있는 단일 라이브러리 결함이며(v1.2·v1.3), BoringSSL에는 같은 버그 클래스가 생길 설정 문법이 없고 OpenSSH는 key_share/HRR 구조가 없어 교차 구현 패턴의 증거는 없습니다. 반면 "하이브리드를 광고했는데 HRR 없이 고전 그룹으로 협상"이라는 표면 증상은 v1.1에서 OpenSSL 명시적 single tuple과 BoringSSL의 정상 동작으로도 나타났고, 측정한 감사 경로는 이를 경고하지 않았습니다.

## 감사 가시성

[확실] v1.2 60건의 client `-msg` 로그·서버 로그·tshark 기본 요약에서 `explicit_warning=True`는 0건입니다. 단일 출력 안에서 광고 그룹과 협상 그룹을 함께 확인하는 `mismatch_in_single_output`은 TLS 출력에 광고 그룹이 없어 60/60 `unsupported`였습니다. `s_client -brief`와 keylog는 수집하지 않아 `not_collected`이며, 경고가 없었다고 판정하지 않습니다.

[확실] v1.1의 보존 로그 90건을 동일 기준으로 재계산하면 `explicit_warning=True`는 0건, `mismatch_in_single_output=True`는 OpenSSH 30건뿐이고 TLS 60건은 `unsupported`였습니다.

## v1.1 선행 관측과 데이터 보존

[확실] `docs/research/baselines/raw/v1.1/`에는 JSON·PCAP·client log·capture log 각 90개와 proxy log 30개가 있습니다. 9개 구현×조건 조합마다 r01–r10이 하나씩 있고, 모두 `manipulation_verified=true`입니다.

| 구현 | 조건 | 성공/전체 | HRR | 기록된 그룹/KEX |
|---|---|---:|---:|---|
| OpenSSL | base | 10/10 | 0 | X25519MLKEM768 |
| OpenSSL | classical-first | 10/10 | 0 | X25519 |
| OpenSSL | onpath-strip | 0/10 | 10* | 미완료 |
| BoringSSL | base | 10/10 | 0 | X25519Kyber768Draft00 |
| BoringSSL | classical-first | 10/10 | 0 | X25519 |
| BoringSSL | onpath-strip | 0/10 | 0 | 미완료 |
| OpenSSH | base / ssh-order | 각 10/10 | 해당 없음 | sntrup761x25519-sha512@openssh.com |
| OpenSSH | onpath-strip | 0/10 | 해당 없음 | 미완료 |

* [확실] OpenSSL onpath-strip의 수집 당시 JSON `hrr_present`는 0이지만, PCAP 고정 random 교차 검증으로 10/10 HRR임을 확인했습니다. 원시 JSON은 변경하지 않았습니다.

[확실] v1.1 OpenSSL의 `X25519MLKEM768:X25519`는 하나의 명시적 tuple이므로, 그 안의 수신된 `X25519` key share 수락은 OpenSSL 문서상 동작과 일치합니다. v1.1은 `DEFAULT`나 수정 버전 대조를 시험하지 않았으므로 CVE 증거가 아닙니다.

## 규범 및 범위

[확실] RFC 8446 §4.1.1의 MUST-HRR은 클라이언트가 호환되는 key share를 보내지 않았을 때 적용됩니다. 이미 수락 가능한 key share가 있는 경우 더 선호하는 그룹을 위해 HRR을 보낼 의무는 규정하지 않습니다. 따라서 S1의 HRR 부재 자체와 S3(3.5.5)의 HRR 부재 자체를 RFC 위반으로 주장하지 않습니다.

[확실] OpenSSL 3.5 groups-list 문서는 현재 tuple 안에 수신된 key share가 있으면 ServerHello를, 지원 그룹만 있으면 HRR을 보내는 선택 규칙을 설명합니다. 문서상 기본 목록은 분리된 tuple을 포함하는 반면 `DEFAULT` 확장 경로는 영향을 받은 3.5.5에서 그 구조를 잃었습니다. S3의 버전 대조는 이 구현 정책 불일치에 대한 관측입니다.

[불확실] 결과는 시험한 OpenSSL 서버(3.5.5, 3.5.6, v1.3 변형 4종), client preference, loopback, 고정 명령과 조합별 10회에 한정됩니다. v1.3의 인과 분리는 `85977e0`의 `ssl/t1_lib.c` 변경에 대한 것이며, 3.6 계열은 릴리스 태그 대조만 했습니다. 다른 배포·구성이나 실배포 공격 가능성은 일반화하지 않습니다.

## 공식 참고 자료

1. [RFC 8446, TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html)
2. [OpenSSL 3.5 `SSL_CTX_set1_curves(3)`](https://docs.openssl.org/3.5/man3/SSL_CTX_set1_curves/)
3. [OpenSSL Security Advisory 20260313](https://openssl-library.org/news/secadv/20260313.txt)
4. [CVE-2026-2673 record](https://www.cve.org/CVERecord?id=CVE-2026-2673)
5. [OpenSSL 3.5 fix commit `85977e0`](https://github.com/openssl/openssl/commit/85977e013f32ceb96aa034c0e741adddc1a05e34)
6. [OpenSSL 3.6 fix commit `2157c9d`](https://github.com/openssl/openssl/commit/2157c9d81f7b0bd7dfa25b960e928ec28e8dd63f)
