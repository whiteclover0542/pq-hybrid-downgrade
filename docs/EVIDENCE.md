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

[확실] 별도 캡처 분석 도구로 표본 2건을 교차 확인했습니다(`tshark -r <pcap> -Y tls.handshake.type==2 -T fields -e tls.handshake.random -e tls.handshake.extensions_key_share_group`). 3.5.5 S3 r01은 ServerHello 1건(random `00b70369…`, key share 그룹 29=`X25519`), 3.5.6 S3 r01은 2건(첫 random이 HRR 고정값 `cf21ad74…`, 두 번째 key share 그룹 4588=`X25519MLKEM768`)이었고, 파서 판정 `hrr_pcap_present`와 일치했습니다. 이 기록은 통합 전 v1.2 분석 문서(커밋 `c928b14`)에서 옮겼습니다.

[확실] S4(서버 설정 생략)는 두 버전 20/20에서 HRR 후 hybrid로 끝났습니다. `DEFAULT` 키워드 확장과 설정 생략은 같은 조건이 아니므로 이 값은 결론 판정에 쓰지 않습니다.

## v1.3 인과 분리

[확실] v1.2의 3.5.5→3.5.6 대조에는 수정 커밋 외 변경이 섞여 있으므로, `tools/v13_build_variants.sh`로 네 서버를 별도 prefix에 빌드해 같은 클라이언트·명령·S1–S3 행렬로 조합별 10회, 총 120회를 실행했습니다(`docs/research/baselines/raw/v1.3/`, 종료 코드 0, stderr 0바이트). 수정 커밋 `85977e0`이 바꾼 파일 중 라이브러리 코드는 `ssl/t1_lib.c` 하나이며 나머지는 문서와 테스트입니다.

| 서버 | 출처 | 수정 변경 | libssl.so.3 SHA-256 |
|---|---|---|---|
| 3.5.5-cherrypick | `openssl-3.5.5`(`67b5686b…`) + `85977e0`의 `ssl/t1_lib.c` 변경(patch SHA-256 `0a7e0206a9ca…`) | 있음 | `ef30c6d8de549ce28e5e757362c997b808f2c2c411996737d3a79c00b11012ab` |
| 3.5.6-revert | `openssl-3.5.6`(`286ddeaa…`) − 같은 변경(patch SHA-256 `0b7674abe147…`) | 없음 | `a9d8f36e38b258704e483a2872ab9de32ee4d0110aac098177cfc588f92c5279` |
| 3.6.1 | `openssl-3.6.1`(`c9a9e5b1…`), `2157c9d` 미포함 | 없음 | `fb70fdbf1a67de864a4f7b61829f30d86d558dbc023404affbee2b1cccdcad61` |
| 3.6.2 | `openssl-3.6.2`(`fe686e15…`), `2157c9d` 포함 | 있음 | `708d5e708526c65c1af8737d59e7ddf21d7d03276921944e1e9a1e0356e2c619` |

[확실] 빌드 스크립트 출력과 설치 후 확인(`docs/research/baselines/raw/v1.3-build.log`: 태그 commit, 수정 커밋 조상 여부, patch SHA-256, libssl SHA-256, 서버별 `ldd` 로드 경로, RPATH/RUNPATH 없음)을 원시 데이터와 함께 보존합니다. 기준 설치의 libssl은 3.5.5 `a785209382213c37…`, 3.5.6 `aff23fc605b58c6f…`로, 여섯 서버의 libssl 해시가 모두 다릅니다. 패치 변형의 `openssl` CLI 바이너리는 원본과 같으므로(3.5.5-cherrypick은 `7b1a89948e5e…`, 3.5.6-revert는 `88a896e54ede…`), 각 기록의 `provenance.server_libssl_sha256`으로 서버를 구분합니다. 클라이언트는 120회 모두 3.5.5 바이너리(`7b1a89948e5e…`)입니다.

| 서버 | S1 HRR / 그룹 | S2 HRR / 그룹 | S3 `DEFAULT` HRR / 그룹 |
|---|---|---|---|
| 3.5.5-cherrypick | 0/10 · X25519 | 10/10 · X25519MLKEM768 | 10/10 · X25519MLKEM768 |
| 3.5.6-revert | 0/10 · X25519 | 10/10 · X25519MLKEM768 | 0/10 · X25519 |
| 3.6.1 | 0/10 · X25519 | 10/10 · X25519MLKEM768 | 0/10 · X25519 |
| 3.6.2 | 0/10 · X25519 | 10/10 · X25519MLKEM768 | 10/10 · X25519MLKEM768 |

[확실] `cd tools && python -m faultinject.analyze --v13`의 판정은 `Causal-isolation verdict: consistent`입니다. 120건 모두 클라이언트 전제가 PCAP으로 검증됐고, 성공 120/120, HRR 로그·PCAP 판정 일치, 실제 ServerHello 1개였습니다. S3 결과는 `ssl/t1_lib.c`의 수정 변경 하나로 뒤집혔고, 3.5와 3.6 두 계열에서 같은 방향으로 갈렸습니다.

## OpenSSL 3.6 인과 분리(v1.7, E6 보완)

[확실] v1.3의 3.6 계열은 릴리스 태그 대조였으므로, 같은 스크립트(`tools/v13_build_variants.sh 3.6.1-cherrypick 3.6.2-revert`)로 3.6 수정 커밋 `2157c9d`의 `ssl/t1_lib.c` 변경만 적용·되돌린 두 서버를 빌드했습니다. `2157c9d`가 바꾼 파일 중 라이브러리 코드는 `ssl/t1_lib.c` 하나입니다(나머지는 CHANGES.md, NEWS.md, 문서, 테스트). 빌드 출력은 `docs/research/baselines/raw/v1.7-build36.log`, `ldd` 로드 경로와 RPATH/RUNPATH 없음 확인은 `v1.7-ldd36.log`에 있습니다.

| 서버 | 출처 | 수정 변경 | libssl.so.3 SHA-256 |
|---|---|---|---|
| 3.6.1-cherrypick | `openssl-3.6.1`(`c9a9e5b1…`) + `2157c9d`의 `ssl/t1_lib.c` 변경(patch SHA-256 `bf6d0d90405d…`) | 있음 | `c0639575928810269980ad5eca14becd035fa0b3653851c193890273abb77256` |
| 3.6.2-revert | `openssl-3.6.2`(`fe686e15…`) − 같은 변경(patch SHA-256 `3b7a2bb86d67…`) | 없음 | `8aea8de16e26075ae027ef08abaf8b2a4c0a4ece1822346cb7311f0e5d0ec1cb` |

[확실] 같은 클라이언트(3.5.5, 고전 우선 광고)와 S1–S3로 조합별 10회, 총 60회를 실행했습니다(`docs/research/baselines/raw/v1.7-openssl36/`, 종료 코드 0, stderr 0바이트). 60건 모두 전제 검증과 핸드셰이크 성공. S1은 두 서버 모두 HRR 0/10·X25519, S2는 HRR 10/10·X25519MLKEM768, S3는 3.6.1-cherrypick HRR 10/10·X25519MLKEM768, 3.6.2-revert HRR 0/10·X25519입니다. `cd tools && python -m faultinject.analyze --v17`의 판정은 `3.6 causal-isolation verdict: consistent`입니다. 이로써 3.6 계열의 차이도 태그 대조의 추론이 아니라 `2157c9d`의 `ssl/t1_lib.c` 변경 하나로 설명됩니다.

## 연구 질문에 대한 답

[추정] 착수 질문(`docs/PROPOSAL.md`: 협상 로직 결함에 의한 하이브리드 PQ 다운그레이드가 특정 라이브러리의 우연한 버그인가, 여러 구현체에 걸친 일반적 패턴인가)에 대해, 시험 범위의 답은 다음과 같습니다. 결함은 OpenSSL에서 확인됐고 `ssl/t1_lib.c`의 수정 변경 하나로 켜지고 꺼집니다(v1.2·v1.3). BoringSSL에는 같은 버그 클래스가 생길 설정 문법이 없고 OpenSSH는 key_share/HRR 구조가 없어, 동등 조건을 만들 수 없었으므로 교차 구현 패턴의 증거는 얻지 못했습니다(다른 구현이 안전하다는 판정은 아닙니다). 반면 "하이브리드를 광고했는데 HRR 없이 고전 그룹으로 협상"이라는 표면 증상은 v1.1에서 OpenSSL 명시적 single tuple과 BoringSSL의 정상 동작으로도 나타났고, 측정한 감사 경로는 이를 경고하지 않았습니다.

[추정] v1.5·v1.6 이후의 답: 결함 자체는 OpenSSL 한 라이브러리의 것이지만, 하이브리드 사용 여부가 구현마다 다른 협상 함수(세 유형)로 정해지고 기본 출력에 드러나지 않는 구조는 시험한 다섯 TLS 구현 전반에 공통입니다. 기본 설정 클라이언트와 기본 설정 nginx·Caddy를 직접 연결한 36회에서도 nginx는 BoringSSL을 제외한 다섯 클라이언트에 하이브리드를, Caddy 2.6.2는 다섯 클라이언트에 X25519를 협상했습니다. Caddy–rustls 3회는 ServerHello 없이 실패했으며 원인은 기록으로 특정할 수 없습니다. 논문은 공격자에 의한 "다운그레이드"와 공격자 없는 "PQ 누락"을 구분합니다.

## 하이브리드 우선 클라이언트(v1.4, E7)

[확실] 같은 3.5.5 클라이언트 바이너리의 그룹 설정만 `X25519MLKEM768:*X25519`로 바꾸어(`*`는 key share를 보낼 그룹), 3.5.5/3.5.6 서버 × S1–S3 × 10회, 총 60회를 실행했습니다(`docs/research/baselines/raw/v1.4/`, 종료 코드 0, stderr 0바이트). 60건 모두 캡처의 ClientHello가 `supported_groups` = `[0x11ec, 0x001d]`(하이브리드 1순위), `key_share` = `[0x001d]`였습니다.

| 서버 | S1 단일 tuple | S2 tuple 경계 | S3 `DEFAULT` |
|---|---|---|---|
| 3.5.5 | HRR 0/10 · X25519 | HRR 10/10 · X25519MLKEM768 | HRR 0/10 · X25519 |
| 3.5.6 | HRR 0/10 · X25519 | HRR 10/10 · X25519MLKEM768 | HRR 10/10 · X25519MLKEM768 |

[확실] `cd tools && python -m faultinject.analyze --v12 --run-dir ../docs/research/baselines/raw/v1.4`의 판정은 `reproduced`입니다. 결과는 v1.2(고전 1순위 클라이언트)와 같습니다. 클라이언트가 하이브리드를 1순위로 광고했는데도 S1에서는 두 버전 모두 HRR 없이 X25519를 골랐습니다. OpenSSL 선택 규칙은 클라이언트 선호 모드에서도 현재 tuple 안의 수신된 key share를 먼저 택하므로 문서화된 동작입니다. 명시적 경고는 0/60, 단일 출력 동시 식별은 60/60 판정 불가였습니다.

[확실] 경로상 PQ 공개키 바꿔치기(TLS 컴바이너 결합 시험), 경로상 그룹 순서 조작, 패킷 길이를 보정한 SSH KEX 제거는 수행하지 않았으며 향후 과제로 남깁니다.

## 다섯 TLS 구현의 협상 함수 비교(v1.5, E8)

[확실] 고정 OpenSSL 3.5.5 클라이언트(C1 `X25519MLKEM768:X25519`, C2 `X25519MLKEM768:*X25519`, C3 `X25519:X25519MLKEM768`)를 하이브리드를 먼저 나열한 다섯 TLS 서버에 연결해 조합별 5회, 총 105회를 실행했습니다(`docs/research/baselines/raw/v1.5/`, 종료 코드 0, stderr 0바이트). 105건 모두 캡처에서 클라이언트 전제(광고 순서와 key share)가 확인됐고, 핸드셰이크가 완료됐으며, 오류 없이 종료했습니다. 재집계: `cd tools && python -m faultinject.v15 --report ../docs/research/baselines/raw/v1.5`.

[확실] 서버: OpenSSL 3.5.6(`X25519MLKEM768:X25519`, 같은 설정 + `-serverpref`, `X25519MLKEM768/X25519`), BoringSSL(`bssl server`, 2024-08 빌드 `7fb4d3d`, `-curves X25519MLKEM768:X25519`), Go 1.26.0 `crypto/tls` 최소 서버(`CurvePreferences` = X25519MLKEM768, X25519; SHA-256 `c3a228dbb129…`), NSS 3.120 `selfserv`(`-I x25519mlkem768,x25519`), rustls 0.23.45(aws-lc-rs, `kx_groups` = X25519MLKEM768, X25519; SHA-256 `8f5b8cd492ef…`). 빌드 출력은 `docs/research/baselines/raw/v1.5-setup.log`에 있습니다.

| 서버 | C1 | C2 | C3 | 유형 |
|---|---|---|---|---|
| OpenSSL 단일 tuple | 하이브리드 | 고전, HRR 0/5 | 고전 | key share 우선 |
| OpenSSL 단일 tuple + `-serverpref` | 하이브리드 | 고전, HRR 0/5 | 고전 | key share 우선 |
| NSS | 하이브리드 | 고전, HRR 0/5 | 고전 | key share 우선 |
| BoringSSL | 하이브리드, HRR 0/5 | HRR 5/5 → 하이브리드 | 고전, HRR 0/5 | 클라이언트 순서 |
| rustls | 하이브리드 | HRR 5/5 → 하이브리드 | 고전 | 클라이언트 순서 |
| Go | 하이브리드 | HRR 5/5 → 하이브리드 | HRR 5/5 → 하이브리드 | 서버 순서 |
| OpenSSL tuple 경계 | 하이브리드 | HRR 5/5 → 하이브리드 | HRR 5/5 → 하이브리드 | 서버 순서 |

[확실] 문서 대조: OpenSSL은 `SSL_CTX_set1_curves(3)` 의사코드와 일치합니다. Go 문서는 "The order of the list is ignored, and key exchange mechanisms are chosen from this list using an internal preference order"라고 밝히며 관측과 일치합니다. rustls 문서는 `kx_groups`를 "in preference order"라고만 적고 서버 쪽 선택 규칙은 적지 않습니다. BoringSSL과 NSS의 서버 선택 규칙은 공개 문서에서 찾지 못해 소스 코드로 확인했습니다(아래 "BoringSSL·NSS 선택 규칙의 소스 근거").

[확실] 시험 중 BoringSSL 서버와의 연결에서 핸드셰이크 완료 뒤 클라이언트가 `decode_error` 경고로 끊는 경우가 1회 시험 실행에서 간헐적으로 있었습니다. 본 실행 105회에서는 나타나지 않았고, 그룹 선택(ServerHello와 HRR)과는 무관합니다. 이를 구분하려고 기록에 핸드셰이크 완료 여부(`New, TLSv1.3` 출력)를 따로 남깁니다.

[확실] 최신 BoringSSL commit `697ee71a13f6c2f6a9626337131a6bb78f31e68b`로 BoringSSL 행만 C1–C3 각 3회 재실행했습니다(`docs/research/baselines/raw/v1.5-boringssl-latest/`, 바이너리 SHA-256 `2553dab4630bb29a0b1e1908c452f5406d5d8fae61c2c20a5288e3b38e873419`, stderr 0바이트). C1은 HRR 0/3·`X25519MLKEM768`, C2는 HRR 3/3·`X25519MLKEM768`, C3는 HRR 0/3·`X25519`로, 2024-08 빌드의 같은 클라이언트 순서 유형과 일치했습니다. 이는 두 시점의 시험 조건 결과가 같다는 관측이며, 모든 BoringSSL 배포판의 기본값을 뜻하지는 않습니다.

## BoringSSL·NSS 선택 규칙의 소스 근거

[확실] BoringSSL(시험한 빌드의 체크아웃 `/root/pq-hybrid-phase2/boringssl`, `git rev-parse HEAD` = `7fb4d3da5082225c7180267e9daad291887ce982`): `ssl/extensions.cc` 323–360행 `tls1_get_shared_group`은 `ssl->options & SSL_OP_CIPHER_SERVER_PREFERENCE`가 참이면 `pref = groups`(서버 목록), 아니면 `pref = hs->peer_supported_group_list`(클라이언트 목록)로 두고, `pref` 순서로 처음 겹치는 그룹을 반환합니다. `ssl/tls13_server.cc` 471행은 이 함수로 그룹을 정하고, 478–479행의 `ssl_ext_key_share_parse_clienthello`로 그 그룹의 key share 유무를 본 뒤, 581–586행에서 key share가 없으면 HRR 상태로 넘어갑니다. `bssl server`는 서버 선호 옵션을 켜지 않았으므로 클라이언트 순서 유형과 일치합니다.

[확실] NSS(GitHub 미러 `nss-dev/nss`, 태그 `NSS_3_120_RTM`): `lib/ssl/tls13con.c`의 `tls13_NegotiateKeyExchange`는 `ss->namedGroupPreferences`(서버 선호 순)를 돌며 첫 활성 그룹을 선호 그룹으로 정하고, 그 그룹의 key share가 없으면 다음 활성 그룹의 key share를 봅니다(2091–2128행). 그 그룹이 `tls13_isGroupAcceptable`(2016–2033행, `e = 2`, `offered->bits`가 선호 그룹 `bits ± e` 안)을 만족하면 그 그룹으로 확정합니다. `lib/ssl/sslsock.c` 170–171행은 `HYGROUP(mlkem768, x25519, 256, …)`와 `{ ssl_grp_ec_curve25519, 256, … }`로 두 그룹을 모두 256비트로 정의합니다. 따라서 하이브리드 다음에 X25519를 둔 서버는 X25519 key share만 받으면 HRR 없이 X25519를 택하며, 관측된 key share 우선 유형과 일치합니다.

[확실] Ubuntu의 시험 패키지(`libnss3`, `libnss3-tools` 모두 `2:3.120-1ubuntu2.1`)에 적용된 소스 패치 목록과 검색 결과는 `docs/research/baselines/raw/nss-ubuntu-patches-20260929.log`에 보존했습니다. 그 목록의 다섯 패치는 `tls13con.c` 또는 `sslsock.c`를 직접 참조하지 않았습니다.

[불확실] 패치 이름·직접 참조가 없다는 사실만으로 다른 코드 경로를 통한 배포판 차이가 없다고 증명되지는 않습니다. 관측 결과는 업스트림 소스 규칙과 일치합니다.

## 클라이언트 기본값과 실제 서버 소프트웨어(v1.6, E9)

[확실] `docs/research/baselines/raw/v1.6/`에 36회 기록이 있습니다(실행 stderr 0바이트, `v1.6-run.stdout.log`·`v1.6-run.stderr.log`). 재집계: `cd tools && python -m faultinject.v16 --report ../docs/research/baselines/raw/v1.6`. 설치 버전과 클라이언트 해시는 `docs/research/baselines/raw/v1.6-setup.log`에 있습니다(콘솔 출력을 옮겨 적은 기록): nginx `1.28.3-2ubuntu1.11`, caddy `2.6.2-14`, openssl/libssl3t64 `3.5.5-1ubuntu3.5`, curl `8.18.0-1ubuntu2.7`, libnss3 `2:3.120-1ubuntu2.1`, Go 클라이언트 SHA-256 `5c59c2029ceb…`, rustls 클라이언트 `0f96dba3a50b…`.

[확실] E9a(기본 설정 클라이언트 → OpenSSL 3.5.6 기본 서버, 각 3회, 3회 모두 같은 결과):

| 클라이언트 | supported_groups | key_share | 협상 그룹 |
|---|---|---|---|
| OpenSSL 3.5.5 | X25519MLKEM768, X25519, 0x0017, 0x001e, 0x0018, 0x0019, 0x0100, 0x0101 | X25519MLKEM768, X25519 | X25519MLKEM768 |
| curl(시스템 OpenSSL) | 위와 같음 | X25519MLKEM768, X25519 | X25519MLKEM768 |
| Go 1.26 | X25519MLKEM768, X25519, 0x0017, 0x0018, 0x0019 | X25519MLKEM768, X25519 | X25519MLKEM768 |
| rustls 0.23.45 | X25519MLKEM768, X25519, 0x0017, 0x0018 | X25519MLKEM768, X25519 | X25519MLKEM768 |
| NSS 3.120 | X25519MLKEM768, X25519, 0x0017, 0x0018, 0x0019, 0x11eb, 0x11ed, 0x0100–0x0104 | X25519MLKEM768 | X25519MLKEM768 |
| BoringSSL(2024-08 빌드) | X25519, 0x0017, 0x0018 | X25519 | X25519 |

[확실] E9a 기록의 `handshake_result`는 OpenSSL 외 클라이언트에서 `failure`입니다. 성공 판정 문자열이 OpenSSL `s_client` 출력 형식이기 때문이며, 이 조사는 ClientHello와 ServerHello 그룹만 판정합니다.

[확실] E9b(기본 설정 서버 ← 고정 OpenSSL 3.5.5 클라이언트 C1–C3, 각 3회): 18건 모두 클라이언트 전제 확인, `handshake_result=success`.

| 서버 | C1 | C2 | C3 |
|---|---|---|---|
| nginx 1.28.3 | X25519MLKEM768, HRR 0/3 | HRR 3/3 → X25519MLKEM768 | HRR 3/3 → X25519MLKEM768 |
| Caddy 2.6.2 | HRR 3/3 → X25519 | X25519, HRR 0/3 | X25519, HRR 0/3 |

[추정] nginx는 `ssl_ecdh_curve`를 두지 않으면 OpenSSL 내장 기본 그룹 목록을 쓰며, 관측된 서버 순서 동작은 하이브리드를 첫 tuple로 두는 그 목록과 일치합니다. Caddy 2.6.2에는 Go 1.25.0의 `tlsmlkem=0`이 확인됐지만, Caddy와 Go를 따로 고정한 인과 분리 실험은 하지 않았습니다.

[확실] E9c는 기본 설정 클라이언트 여섯 개를 기본 설정 nginx·Caddy 2.6.2에 직접 연결한 36회입니다(`docs/research/baselines/raw/v1.6-direct/`, 각 조합 3회, stderr 0바이트). nginx는 BoringSSL에 X25519 3/3, OpenSSL·curl·Go·NSS·rustls에 `X25519MLKEM768` 3/3을 협상했습니다. Caddy는 BoringSSL·OpenSSL·curl·Go·NSS에 X25519 3/3을 협상했고, rustls 3/3은 `server_hello_count=0`, `final_negotiated_group=null`인 실패였습니다. rustls의 클라이언트·서버 로그에는 TLS 실패 원인을 식별할 문자열이 없어 SNI·인증서·ALPN 등의 원인을 판정하지 않습니다.

[확실] Caddy 2.6.2의 `go version -m` 및 SHA-256은 `docs/research/baselines/raw/v1.6-direct/caddy-2.6.2-build-info.log`에 보존했습니다. 이 바이너리는 Go 1.25.0이고 `DefaultGODEBUG`에 `tlsmlkem=0`이 있습니다. 공식 Caddy 2.11.4 바이너리의 SHA-512 검증값과 `go version -m` 출력은 `docs/research/baselines/raw/v1.6-caddy-2.11.4/caddy-2.11.4-provenance.log`에 보존했으며, 이 바이너리는 Go 1.26.3입니다.

[확실] Caddy 2.11.4 대조 실행(`docs/research/baselines/raw/v1.6-caddy-2.11.4/`)에서 C1은 HRR 0/3·`X25519MLKEM768`, C2와 C3는 각각 HRR 3/3 뒤 `X25519MLKEM768`이었습니다. 이는 같은 하네스의 Caddy 2.6.2 결과와 다릅니다.

[추정] Caddy 2.6.2의 `tlsmlkem=0`과 최신 대조의 결과 차이는 Go TLS의 ML-KEM 기본값이 원인이라는 설명과 일치하지만, Caddy와 Go 버전이 함께 바뀌었으므로 이 실험만으로 단일 원인을 인과적으로 확정하지는 않습니다.

## 브라우저 ClientHello(v1.7, E10)

[확실] `tools/v17_setup.sh`로 Chrome for Testing Stable 154.0.8037.57의 `chrome-headless-shell`(zip SHA-256 `5a6979d0ab7c…`, 실행 파일 `60c03e8882f4…`)과 Firefox 156.0.1 공식 배포판(tar SHA-256 `7405c0487fa3…`, 실행 파일 `7ea3daf0cdbe…`)을 저장소 밖에 설치했습니다(`docs/research/baselines/raw/v1.7-setup.log`). 두 브라우저를 headless로 v1.6과 같은 OpenSSL 3.5.6 기본 서버에 연결해 각 3회를 기록했습니다(`docs/research/baselines/raw/v1.7/`, 실행 stderr 0바이트).

| 브라우저 | supported_groups | key_share | 협상 그룹 |
|---|---|---|---|
| Chrome 154(headless shell) | GREASE, X25519MLKEM768, X25519, 0x0017, 0x0018 | GREASE, X25519MLKEM768, X25519 | X25519MLKEM768, HRR 0/3 |
| Firefox 156.0.1(headless) | X25519MLKEM768, X25519, 0x0017, 0x0018, 0x0019 | X25519MLKEM768, X25519, 0x0017 | X25519MLKEM768, HRR 0/3 |

[확실] Chrome의 GREASE 값은 연결마다 달랐습니다(0xbaba, 0x8a8a, 0x0a0a). 보고 함수는 RFC 8701 GREASE 형식(0x?a?a, 두 바이트 동일)을 `GREASE`로 묶어 집계하고, 원시 JSON에는 실제 값이 남아 있습니다. 브라우저 기록의 `handshake_result`는 OpenSSL 외 클라이언트이므로 `failure`로 남습니다.

[추정] `v1.7-setup.log`의 Firefox `ldd` 줄(`libxul.so`의 `NSS_3.126` 및 `libmozsandbox.so` 등 not found)은 시스템 경로만 검사한 결과입니다. Firefox는 실행 시 배포판 디렉터리에 함께 들어 있는 NSS와 라이브러리를 읽으며, 실제 실행은 `--version`과 3회 연결 모두 정상이었습니다.

[불확실] headless 빌드와 새 프로필의 기본값이며, 일반 배포판 브라우저의 원격 설정(field trial 등)이나 모바일 빌드의 key share 전략은 확인하지 않았습니다.

## 실제 기본 클라이언트 확대와 Botan C3 정책 대조(v1.8, E11)

[확실] `docs/research/baselines/raw/v1.8/`에는 기본값 실행 24건(후보 8개 × 3회)과 환경 목록 JSON 1개가 있습니다. 각 실행은 OpenSSL 3.5.6 기본 서버에 연결했고, 후보의 그룹 목록·key share를 강제로 설정하지 않았습니다. 재집계 명령은 `cd tools && python -m faultinject.v18 --report ../docs/research/baselines/raw/v1.8`입니다. 최초 실행 stdout은 당시의 잘못된 Botan C2 파생 라벨을 역사적으로 보존하고, 수정된 JSON을 다시 집계한 출력은 `v1.8-reclassification.log`에 보존했습니다.

| 분류 | 클라이언트 | 3회 관측 |
|---|---|---|
| C1 | wolfSSL, s2n-tls, Node.js, Python | 하이브리드를 첫 `supported_groups`와 초기 `key_share`에 포함 |
| C3 | Botan 3.10.0 | `X25519`, P-256, `X25519MLKEM768`, …을 광고하고 `X25519` share만 전송 |
| PQ 미적용 | GnuTLS, Java, mbedTLS | 기본 `supported_groups`에 하이브리드가 없음 |

[확실] 이 표본에는 하이브리드를 첫 순위로 광고하면서 하이브리드 share를 미루는 C2가 없습니다. 따라서 실제 기본값에서 C2형 PQ 누락을 재현하지 않았습니다. GnuTLS를 사용하는 curl은 별도 후보로 시험하지 않았고, 시스템 curl은 OpenSSL 기반 대조군입니다.

[확실] `docs/research/baselines/raw/v1.8-e8/`에는 Botan C3 서버유형 대조 15건(서버 5개 × 3회)과 환경 목록 JSON 1개가 있습니다. 재집계 명령은 `cd tools && python -m faultinject.v18 --report ../docs/research/baselines/raw/v1.8-e8`입니다. 수정 후 집계 출력은 `v1.8-e8-reclassification.log`에 보존했습니다.

| 서버 선택 유형 | 서버 | 결과(각 3/3) |
|---|---|---|
| key-share 우선 | OpenSSL 단일 tuple, OpenSSL 단일 tuple + `-serverpref`, NSS | HRR 없음 · `X25519` |
| 클라이언트 순서 | BoringSSL | HRR 없음 · `X25519` |
| 서버 순서 | OpenSSL 3.5.6 기본 설정, Go | HRR 뒤 `X25519MLKEM768` |

[확실] Botan은 C3이므로 위 고전 결과는 클라이언트가 고전을 첫 순위에 둔 협상입니다. 양 끝점의 하이브리드 지원과 고전 협상은 본 연구의 조작적 PQ 누락 정의에는 맞지만, C2의 실제 사례나 서버가 하이브리드 우선 선호를 무시했다는 증거는 아닙니다. 이 대조가 보이는 범위는 실제 C3 기본값의 결과가 시험한 서버 선택 유형에 의존한다는 점입니다.

[확실] `docs/research/baselines/raw/v1.8-diagnose/mbedtls-rng-init/`의 15개 파일은 RNG 초기화가 빠진 mbedTLS 탐색 실행의 진단 기록입니다. 최종 표본과 분리해 보존하며, 집계·논문 수치·v1.8 재현 ZIP에는 포함하지 않습니다.

## 감사 가시성

[확실] v1.2 60건의 client `-msg` 로그·서버 로그·tshark 기본 요약에서 `explicit_warning=True`는 0건입니다. 단일 출력 안에서 광고 그룹과 협상 그룹을 함께 확인하는 `mismatch_in_single_output`은 TLS 출력에 광고 그룹이 없어 60/60 `unsupported`였습니다. `s_client -brief`와 keylog는 수집하지 않아 `not_collected`이며, 경고가 없었다고 판정하지 않습니다.

[확실] v1.1의 보존 로그 90건을 동일 기준으로 재계산하면 `explicit_warning=True`는 0건, `mismatch_in_single_output=True`는 OpenSSH 30건뿐이고 TLS 60건은 `unsupported`였습니다.

[확실] 상세 출력(v1.7): E5–E10과 인과 분리·최신 대조의 보존 PCAP 537개(v1.2, v1.3, v1.4, v1.5, v1.5-boringssl-latest, v1.6, v1.6-direct, v1.6-caddy-2.11.4, v1.7-openssl36, v1.7)에 `tshark -r <pcap> -V`(TShark 4.6.4)를 적용했습니다. ServerHello가 있는 534개 모두에서 ClientHello의 `Supported Group` 목록과 마지막 ServerHello의 `Key Share Entry` 그룹이 한 출력에 나타났고, 그 그룹은 기록된 `final_negotiated_group`과 534/534 일치했습니다. 나머지 3개는 ServerHello가 없는 Caddy 2.6.2–rustls 연결입니다. 경고 문구(`WARNING_RE`)와 연결 순서(Sequence) 외 전문가 정보(Warning·Error)는 537개 모두 0건입니다. 실행별 결과는 `docs/research/baselines/raw/v1.7-tshark-verbose-audit.json`에 있습니다. `phase-4/`, `v1.1/`, `v1.2-s4/`, 진단 디렉터리의 PCAP은 이 재측정에 넣지 않았습니다.

[확실] `s_client -trace` 재실행(v1.7, 3.5.5 S1·S3, 3.5.6 S3 각 3회): 9건 모두 클라이언트 로그 한 곳에 광고 그룹(`ecdh_x25519`, `X25519MLKEM768`)과 협상 그룹이 이름으로 나타났습니다(3.5.5 서버 6건은 `Peer Temp Key: X25519`, 3.5.6 S3 3건은 `Negotiated TLS1.3 group: X25519MLKEM768`). 경고 문구(`WARNING_RE`)는 0건입니다. 모든 로그에 있는 연결 종료 alert(`Level=warning(1)` … `close notify`)는 TLS 경고 수준의 정상 종료 알림이므로 정의상 경고 문구에서 제외됩니다. 3.5.5 S1·S3 로그에는 서버의 EncryptedExtensions `supported_groups`가 `X25519MLKEM768`을 1순위로 찍혔고(S3는 전체 기본 목록), 하이브리드를 협상한 3.5.6 S3는 EncryptedExtensions에 확장이 없었습니다. OpenSSL 3.5.6(`286ddeaa`) `ssl/statem/extensions_srvr.c` 1667–1699행의 `tls_construct_stoc_supported_groups`는 협상 그룹이 서버의 첫 그룹과 같으면 이 확장을 보내지 않습니다. 원시 JSON의 `audit.trace` 중 HRR이 있는 3.5.6 S3 3건의 `server_groups`는 수정 전 파서 값이므로, 보고 함수는 보존된 클라이언트 로그에서 다시 계산합니다.

[추정] 상세 출력은 PQ 누락을 판단할 재료를 한 출력에 모아 주지만, 경고하지는 않으며 S1의 문서화된 동작과 S3의 결함을 구분하지도 않습니다.

## 경로상 조작과 기준선(v1.0, E1·E2)

[확실] `docs/research/baselines/raw/phase-4/`에는 3개 구현 × 2개 결함 유형 × 10회 = 60회 기록이 있고, 모두 `manipulation_verified=true`입니다(`cd tools && python -m faultinject.analyze`). OpenSSL은 이 단계에서 oqs-provider 0.9.0과 함께 사용했습니다.

| 구현 | E1 고전 전용 제시(기준선) | E2 PQ 성분 변조 | E2 거부 원인(10/10 동일) |
|---|---|---|---|
| OpenSSL | 성공 10/10, `X25519` | 실패 10/10 | 서버 `ML-KEM-768 invalid public 't' vector`, 클라이언트 `illegal parameter` 경고 → 키 형식 검증 |
| BoringSSL | 성공 10/10, `X25519` | 실패 10/10 | 서버 `BAD_ECPOINT`(`ssl_key_share.cc`), 클라이언트 `DECODE_ERROR` → key share 해석 |
| OpenSSH | 성공 10/10, `curve25519-sha256` | 실패 10/10 | 클라이언트 `incorrect signature` → 교환 해시 서명 검증 |

[확실] E1은 클라이언트가 고전만 제시한 기준선이므로 다운그레이드 공격의 증거가 아닙니다. E2는 하이브리드 공개값의 PQ 성분만 비트 반전했습니다. TLS 두 구현의 거부는 결합 검증 이전의 키 형식 검증에서 일어났으므로, TLS 컴바이너 결합 자체는 시험되지 않았습니다. 초기 분석의 "바인딩 방어 성공" 해석을 이렇게 정정합니다. OpenSSH의 거부는 교환 해시에 의한 결합 방어입니다.

[확실] v1.1 경로상 하이브리드 제거(E3)의 실패 원인도 10/10 동일했습니다: OpenSSL 클라이언트 `bad record mac`(HRR 후), BoringSSL 클라이언트 `BAD_DECRYPT` → transcript 결합. OpenSSH 서버 `padding error`·`message authentication code incorrect` → KEXINIT 수정으로 패킷 형식이 깨진 것으로, 협상 방어는 판정하지 않습니다.

[확실] v1.1 OpenSSH `ssh-order` 조건은 `tools/faultinject/conditions.py`에서 `base`와 같은 `KexAlgorithms` 설정으로 실행되어, 사실상 같은 조건의 반복입니다.

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

[불확실] 결과는 시험한 OpenSSL 서버(3.5.5, 3.5.6, v1.3 변형 4종, v1.7 3.6 변형 2종), client preference, loopback, 고정 명령과 조합별 10회에 한정됩니다. 인과 분리는 3.5 계열은 `85977e0`, 3.6 계열은 `2157c9d`의 `ssl/t1_lib.c` 변경에 대한 것입니다. 다른 배포·구성이나 실배포 공격 가능성은 일반화하지 않습니다.

## 공식 참고 자료

1. [RFC 8446, TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html)
2. [OpenSSL 3.5 `SSL_CTX_set1_curves(3)`](https://docs.openssl.org/3.5/man3/SSL_CTX_set1_curves/)
3. [OpenSSL Security Advisory 20260313](https://openssl-library.org/news/secadv/20260313.txt)
4. [CVE-2026-2673 record](https://www.cve.org/CVERecord?id=CVE-2026-2673)
5. [OpenSSL 3.5 fix commit `85977e0`](https://github.com/openssl/openssl/commit/85977e013f32ceb96aa034c0e741adddc1a05e34)
6. [OpenSSL 3.6 fix commit `2157c9d`](https://github.com/openssl/openssl/commit/2157c9d81f7b0bd7dfa25b960e928ec28e8dd63f)
