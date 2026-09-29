# OpenSSL group tuple 경계와 CVE-2026-2673: `DEFAULT` 설정에서의 HRR 생략과 수정 버전 대조

- 저자: whiteclover0542
- 문서 갱신: 2026-09-28
- 데이터 기준: v1.2 60회 실행(2026-09-28) + v1.1 P2 최종 데이터셋(2026-09-25, 선행 관측)

## 초록

[확실] 본 연구는 하이브리드 PQ 키 교환(`X25519MLKEM768`)과 고전 키 교환(`X25519`)을 함께 광고하되 초기 `key_share`에는 `X25519`만 보내는 하나의 고정된 OpenSSL 3.5.5 native-only 클라이언트를 사용해, 서버 group-list 설정(S1 `X25519MLKEM768:X25519`, S2 `X25519MLKEM768/X25519`, S3 `DEFAULT`)과 서버 버전(3.5.5/3.5.6, 수정 커밋 `85977e0` 조상 확인됨)의 2×3 조합마다 10회씩 총 60회를 실행했습니다. S3(`DEFAULT`)에서 3.5.5는 10/10 반복 모두 PCAP HelloRetryRequest(HRR) 없이 classical `X25519` handshake를 완료했고(HRR (PCAP)=0/10, classical=10/10), 같은 S3에서 3.5.6은 10/10 반복 모두 PCAP HRR을 보낸 뒤 hybrid `X25519MLKEM768` handshake를 완료했습니다(HRR (PCAP)=10/10, hybrid=10/10). 설계 §2.2의 4개 판정 조건(S3 3.5.5 HRR 없는 classical 완료, S3 3.5.6 HRR 있는 hybrid 완료, S1/S2가 문서상 대조 결과를 보임, 각 조합 10회 일관·근거 보존)을 모두 충족하여, 설계 §8 문구대로 "이 고정된 테스트베드에서 CVE-2026-2673 발현 조건과 수정 대조를 재현했다"고 판정합니다.

[확실] 근거 대장(`docs/EVIDENCE.md`의 “규범 및 범위”)은 RFC 8446 §4.1.1의 MUST-HRR 의무가 클라이언트가 이미 수락 가능한 key_share를 보내지 않았을 때에만 적용되므로 S1·S3(3.5.5)의 HRR 부재 자체는 RFC 위반이 아니며, CVE-2026-2673은 OpenSSL이 `DEFAULT` 확장 과정에서 자신이 문서화한 tuple 기반 group-selection 정책(`TLS_DEFAULT_GROUP_LIST`의 tuple 구문)을 스스로 지키지 못한 구현 결함으로 위치 짓는 것이 근거와 일치한다고 결론짓습니다.

[불확실] 이 결과는 시험한 두 OpenSSL 버전·group-list 설정·client preference·loopback 환경·10회 반복에 한정되며, 모든 OpenSSL 배포·구성이나 실배포 공격 가능성을 일반화하지 않습니다.

## 1. 서론

[확실] v1.0은 클라이언트가 CLI로 고전 그룹만 제시한 group-list 실험과 PQ 성분 변조 대조 실험을 수행했습니다. 그 결과는 구성상 고전만 제시하면 고전 협상이 가능하고 변조는 실패한다는 관측이었으나, 클라이언트의 group-list 자체가 이미 고전만 광고하는 동어반복적 구성이었고, `DEFAULT` 경로는 시험하지 않았습니다.

[확실] v1.1은 하이브리드를 광고한 상태에서 `key_share` 순서가 협상·HRR·감사 가시성에 미치는 영향을 교차 구현(OpenSSL, BoringSSL, OpenSSH)으로 측정했습니다. v1.1의 OpenSSL 서버 설정은 `X25519MLKEM768:X25519`라는 하나의 명시적 tuple이었고, 초기 발표 이후 이 결과는 해당 tuple 안에 이미 받은 `X25519` key share를 수락하는 OpenSSL의 문서상 선택 규칙과 일치한다는 해석 보강이 이루어졌습니다(v1.1 §2.3, †HRR 정정 포함). 즉 v1.1의 single tuple 수락은 CVE-2026-2673의 증거가 아니며, v1.1은 이 사실을 숨기지 않고 논문·재현 패키지에 그대로 남깁니다.

[확실] v1.2는 v1.1이 시험하지 않은 것, 즉 `DEFAULT` 키워드가 tuple 구조를 잃는 CVE-2026-2673의 발현 경로 자체를 OpenSSL 3.5.5(발현)와 3.5.6(수정 커밋 `85977e0` 이후)의 직접 대조로 분리해 시험합니다. v1.2는 명시적 single tuple(S1), 명시적 tuple 경계(S2), `DEFAULT`(S3) 세 서버 설정을 두 버전 각각에 적용해, `DEFAULT` 특유의 결함을 다른 정상 tuple 동작과 구분합니다.

## 2. 방법

### 2.1 환경 (A-0)

[확실] 클라이언트와 3.5.5 서버는 기존 설치를 재사용한 동일 바이너리(`/root/pq-hybrid-phase2/install/openssl/bin/openssl`, SHA-256 `7b1a89948e5e2375ae24a47bd579bbd59c48e8f2fcef4508d6c5e943aba46ef1`)입니다. 3.5.6 서버는 별도 prefix에 새로 빌드한 수정 대조군(`/root/pq-hybrid-phase2/install/openssl-3.5.6/bin/openssl`, SHA-256 `88a896e54ede812cc7b944c307d4d159f478ac039f6dc08fa73da6d1cbe447eb`)입니다.

[확실] 3.5.6 소스는 정확히 `openssl-3.5.6` 태그(`git describe --tags --exact-match`, commit `286ddeaac037533bbdce65b3c689e3f7ffebf0f6`)를 가리키며, `git merge-base --is-ancestor 85977e0 HEAD`가 `fix-ancestor=yes`(종료 코드 0)로 수정 커밋 `85977e013f32ceb96aa034c0e741adddc1a05e34`("Fix group tuple handling in DEFAULT expansion")의 조상임을 확인했습니다. 두 버전 모두 `-provider default`만 사용하며(oqsprovider 미로드), `openssl list -tls-groups -tls1_3`에 `X25519MLKEM768`이 있음을 확인했습니다.

### 2.2 고정 클라이언트와 행렬

[확실] 모든 60회는 동일한 OpenSSL 3.5.5 native-only 클라이언트 바이너리와 동일 명령(`-groups X25519:X25519MLKEM768`, ClientHello `supported_groups`에 `X25519`·`X25519MLKEM768` 광고, `key_share`는 `X25519`만 전송)을 사용했습니다. 두 서버 모두 `-serverpref`를 지정하지 않아 OpenSSL 기본값인 client preference로 고정했습니다. 서버 group-list는 S1 `X25519MLKEM768:X25519`, S2 `X25519MLKEM768/X25519`, S3 `DEFAULT`입니다. 필수 표본은 2 버전 × 3 설정 × 10회 = 60회입니다.

### 2.3 HRR 주 판정과 CVE 재현 판정 규칙

[확실] HRR의 주 판정값은 TLS PCAP ServerHello random이 RFC 8446 HelloRetryRequest 고정 random(`cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c`)과 일치하는지 여부입니다. 클라이언트 `-msg` 로그는 보조 증거이며 PCAP 판정을 대체하지 않습니다.

[확실] "CVE-2026-2673이 이 테스트베드에서 재현됐다"는 문구는 설계 §2.2에 따라 다음 네 조건을 모두 만족할 때만 사용합니다: (1) S3에서 3.5.5가 검증된 클라이언트 전제 아래 HRR 없이 classical `X25519` handshake를 완료, (2) 같은 S3에서 3.5.6이 PCAP HRR을 보낸 뒤 `X25519MLKEM768` hybrid handshake를 완료, (3) S1·S2가 각각 명시적 single-tuple 수락과 명시적 tuple 경계 HRR이라는 문서상 대조 결과를 보임, (4) 각 필수 version×setting 조합이 독립 반복 10회에서 위 결과가 일관되고 설정 문자열·바이너리 버전·PCAP·로그가 모두 보존됨.

### 2.4 감사 가시성 정의

[확실] 기존의 하드코딩된 `audit_flags_downgrade()` 결과 대신, v1.2는 경로별 실측 지표 `explicit_warning`(단일 도구 출력에 downgrade/insecure/security warning/policy 서명이 명시되면 참, 출력이 없으면 미확인)과 `mismatch_in_single_output`(단일 출력 안에서 광고 그룹과 협상 결과 그룹을 함께 식별할 수 있으면 참, 그렇지 못하면 미확인 또는 미지원)을 `tools/faultinject/audit.py`로 계산합니다. 실제로 측정한 경로는 클라이언트 `-msg` 로그, 서버 로그, tshark 기본 요약 세 가지입니다. `s_client -brief`와 keylog 두 경로는 v1.2에서 수집하지 않았습니다(클라이언트가 `-state -msg`로 실행되어 `-brief` 출력을 캡처하지 않았고, NSS 키 로그도 남기지 않았습니다); 이 두 경로는 `mismatch_in_single_output="not_collected"`로 고정됩니다.

## 3. 결과

[확실] `python -m faultinject.analyze --v12`(tools/에서 실행) 출력 원문:

```
| server | setting | precondition/n | success | failure | HRR (PCAP) | HRR (log) | hybrid | classical | unknown | explicit warning | single-output mismatch |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 3.5.5 | S1 | 10/10 | 10 | 0 | 0 | 0 | 0 | 10 | 0 | 0 | 0 |
| 3.5.5 | S2 | 10/10 | 10 | 0 | 10 | 10 | 10 | 0 | 0 | 0 | 0 |
| 3.5.5 | S3 | 10/10 | 10 | 0 | 0 | 0 | 0 | 10 | 0 | 0 | 0 |
| 3.5.6 | S1 | 10/10 | 10 | 0 | 0 | 0 | 0 | 10 | 0 | 0 | 0 |
| 3.5.6 | S2 | 10/10 | 10 | 0 | 10 | 10 | 10 | 0 | 0 | 0 | 0 |
| 3.5.6 | S3 | 10/10 | 10 | 0 | 10 | 10 | 10 | 0 | 0 | 0 | 0 |

CVE-2026-2673 verdict: reproduced
```

[확실] S3(`DEFAULT`)만이 두 버전 사이에서 갈렸습니다: 3.5.5는 HRR (PCAP)=0/10·classical=10/10, 3.5.6은 HRR (PCAP)=10/10·hybrid=10/10. S1(명시적 single tuple)은 두 버전 모두 HRR (PCAP)=0/10·classical=10/10로 동일했고, S2(명시적 tuple 경계)는 두 버전 모두 HRR (PCAP)=10/10·hybrid=10/10로 동일했습니다. `explicit warning`·`single-output mismatch` 열은 6개 조합 전부 0이었습니다.

[확실] tshark 교차 확인(3.5.5 S3 r01, 3.5.6 S3 r01): 3.5.5 S3 r01은 `tls.handshake.type==2`(ServerHello) 필터에 1줄만 매치했고 `tls.handshake.random`이 HRR 고정값이 아니었습니다(`key_share_group`=29=`X25519`). 3.5.6 S3 r01은 2줄이 매치했고 첫 줄의 `random`이 정확히 HRR 고정 random(`cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c`)이었으며, 두 번째 줄은 `key_share_group`=4588=`X25519MLKEM768`이었습니다. 이 tshark 매치 수(3.5.5: 0, 3.5.6: 1)는 각 레코드의 파서 판정 `hrr_pcap_present`와 정확히 일치했습니다.

[확실] **선행 관측(v1.1, 2026-09-25, `DEFAULT`·버전 대조 미포함)**: v1.1은 OpenSSL·BoringSSL·OpenSSH 9개 구현×조건 조합을 각 10회씩 실행했습니다. 요약:

| 구현 | 조건 | 전체 | 성공 | 실패 | HRR 있음 | 자동 flag | 기록된 그룹/KEX |
|---|---|---:|---:|---:|---:|---:|---|
| OpenSSL | base | 10 | 10 | 0 | 0 | 0 | X25519MLKEM768 |
| OpenSSL | silent-downgrade | 10 | 10 | 0 | 0 | 0 | X25519 |
| OpenSSL | onpath-strip | 10 | 0 | 10 | 10† | 0 | X25519† |
| BoringSSL | base | 10 | 10 | 0 | 0 | 0 | X25519Kyber768Draft00 |
| BoringSSL | silent-downgrade | 10 | 10 | 0 | 0 | 0 | X25519 |
| BoringSSL | onpath-strip | 10 | 0 | 10 | 0 | 0 | — |
| OpenSSH | base | 10 | 10 | 0 | 0 | 0 | sntrup761x25519-sha512@openssh.com |
| OpenSSH | ssh-order | 10 | 10 | 0 | 0 | 0 | sntrup761x25519-sha512@openssh.com |
| OpenSSH | onpath-strip | 10 | 0 | 10 | 0 | 0 | sntrup761x25519-sha512@openssh.com |

† OpenSSL `onpath-strip`: 수집 당시 JSON의 `hrr_present`는 이 HRR을 놓쳤으나(OpenSSL `-msg`가 HRR을 `ServerHello`로 표기), PCAP 교차 검증으로 10/10 HRR이 있었음을 정정했습니다. 원시 JSON은 수정하지 않았습니다. v1.1 서버는 명시적 single tuple `X25519MLKEM768:X25519`을 사용했으므로, `silent-downgrade`의 `X25519` 수락은 CVE-2026-2673의 `DEFAULT` 경로가 아니라 그 tuple 안의 문서상 선택 규칙과 일치하는 결과입니다(§1, §4).

## 4. 논의

[확실] 근거 대장(`docs/EVIDENCE.md`의 “규범 및 범위”)의 결론은 다음과 같습니다.

- **Q1** (클라이언트가 이미 수락 가능한 key_share를 보냈을 때 서버가 더 선호하는 그룹을 위해 HRR을 보낼 의무가 있는가): RFC 8446 §4.1.1의 MUST-HRR은 "클라이언트가 호환되는 key_share를 보내지 않았을 때"만 적용되는 조건부 의무이며, §4.2.7은 이 경우 SHOULD 수준의 `supported_groups` 힌트만 규정합니다. 따라서 문언상 답은 "의무 없음"입니다. [불확실] 다만 선택적 HRR이 금지되는지는 RFC 8446 문언만으로는 결정되지 않습니다.
- **Q2** (RFC 8446이 그룹 선택 기준을 서버 정책에 맡기는가): §4.1.1은 서버가 독립적으로 그룹을 선택한다고만 말할 뿐 선택 알고리즘을 규정하지 않으므로, [추정] 구체적 기준은 각 구현체의 정책에 맡겨져 있다고 해석하는 것이 합리적입니다.
- **Q3** (S1/S2/S3의 위치): S1·S2·S3(3.5.6)은 RFC 8446 허용 범위 안에 있고 OpenSSL이 문서화한 tuple 선택 의사코드(`SSL_CTX_set1_curves.pod:153-167`)와 정확히 대응합니다. S3(3.5.5)만 RFC 8446 문언 위반은 아니지만, `TLS_DEFAULT_GROUP_LIST`가 정의하는 "/"로 구분된 4개 tuple 구조를 `DEFAULT` 확장 과정에서 잃어 S2와 같은 tuple 경계 HRR이 발생해야 함에도 발생하지 않은, OpenSSL 자신의 문서화된 정책과의 불일치입니다.

[확실] S1과 S3(3.5.5)의 차이는 이 지점에서 드러납니다. S1의 HRR 부재는 명시적 single tuple 안에 이미 X25519MLKEM768과 X25519가 함께 있어 client key-share 루프에서 즉시 매치되는, 의도된 정상 동작입니다. S3(3.5.5)의 HRR 부재는 `DEFAULT`가 문서상 4개의 분리된 tuple로 정의되어 있음에도 그 구조를 잃고 단일 tuple처럼 처리된 결과이므로, 같은 "HRR 없음"이라도 근거가 다릅니다. 따라서 S1은 CVE 증거로 쓰지 않으며, CVE-2026-2673의 발현은 S3(3.5.5)과 S3(3.5.6)의 대조에서만 성립합니다.

[확실] 감사 가시성 실측 결과(§2.4의 정의, `docs/EVIDENCE.md`의 “감사 가시성”): v1.2 60건 전부 `explicit_warning=False`(0건 True)였고, `mismatch_in_single_output`은 60/60이 `"unsupported"`(0건 True, 0건 unknown)였습니다. 이는 OpenSSL `-msg` 로그가 협상 결과 줄만 있고 광고 그룹 줄이 없어 "확인 불가(unsupported)"로 남는다는 v1.1 재계산의 도구 한계가 v1.2에서도 동일하게 재현된 것입니다. v1.1 재계산은 90건 전부 `explicit_warning=False`(unknown 0건)였고, `mismatch_in_single_output`은 openssh 30건만 `True`(TLS 60건은 `"unsupported"`)였습니다. 즉 측정한 세 경로(client `-msg` 로그, 서버 로그, tshark 기본 요약)에서는 S3(`DEFAULT`)의 CVE 발현이 자동 경고되지 않았습니다. `s_client -brief`와 keylog는 수집하지 않았으므로 이 두 경로가 경고를 냈을지는 이 데이터로 판정할 수 없습니다.

[확실] BoringSSL은 근거 대장(`docs/EVIDENCE.md`의 “환경과 대조군”)에 기록한 조사 결과에 따라 v1.2 핵심 CVE 표본에서 제외했습니다. BoringSSL은 `SSL_OP_CIPHER_SERVER_PREFERENCE` + 순서가 있는 평평한(flat) 그룹 ID 목록만 제공하며, OpenSSL의 콜론/슬래시 tuple 구문이나 `DEFAULT` 키워드에 대응하는 설정 문법이 없어("구조화된 tuple을 파싱하다가 평평한 목록으로 잃어버리는" 버그 클래스가 애초에 발생할 수 없는 API 형태), 인위적 동등 조건을 만들지 않고 "OpenSSL `DEFAULT` CVE 비교에 대한 설정 수단을 확인하지 못함"으로 결과를 제한했습니다.

[확실] A-0 재조사에서 v1.1 BoringSSL `silent-downgrade` 조건의 ClientHello `key_share`가 실제로는 `[0x001D, 0x6399]`(X25519, X25519MLKEM768) 두 개였다는 사실이 새로 확인됐습니다(2026-09-28 PCAP 원시 바이트 재해석). 따라서 v1.1 BoringSSL 행은 "고전 키만 제시"가 아니라, 하이브리드 key share도 함께 받은 상태에서 서버가 `X25519`를 선택한 경우로 재해석해야 합니다.

## 5. 한계

[확실] OpenSSL 버전은 3.5.5(재사용 native-only 설치)와 3.5.6(수정 대조군 빌드) 두 개로 고정했습니다. 다른 마이너/패치 버전이나 배포판 패키지의 동작은 일반화하지 않습니다.

[확실] 모든 실행은 loopback(127.0.0.1)에서만 수행했으며, 경로상 네트워크 지연·MITM·실배포 조건은 포함하지 않습니다.

[확실] 서버는 두 버전 모두 client preference 정책(`-serverpref` 미지정) 한 가지로 고정했습니다. server preference를 켠 환경에서의 동작은 시험하지 않았습니다.

[확실] 각 필수 version×setting 조합의 반복 횟수는 10회로 고정했습니다. 더 많은 반복에서 다른 분포가 나올 가능성은 이 표본만으로 배제할 수 없습니다.

[확실] `tools/faultinject/pcap_hello.py` 기반 파서는 TCP로 세그먼트된(여러 TCP segment에 걸쳐 재조립되는) TLS Hello를 처리하지 않습니다. 본 60회는 loopback에서 소규모 핸드셰이크 메시지만 오갔으므로 세그먼트 분할이 관측되지 않았지만, 더 큰 인증서 체인 등으로 메시지가 커지는 환경에서는 이 파서 제약이 판정에 영향을 줄 수 있습니다.

[확실] `s_client -brief`와 keylog 감사 경로는 v1.2 60회 실행에서도 수집하지 않았습니다(클라이언트는 `-state -msg`로 실행되어 `-brief` 출력을 캡처하지 않으며, NSS 키 로그도 남기지 않았습니다).

[확실] S4(서버 group-list 설정 생략, sanity control)는 근거 대장에 기록한 20회 보조 표본으로만 취급했으며, 결론 표본(S1–S3, 60회)에 포함하지 않았습니다.

[확실] 3.5.5→3.5.6에는 수정 커밋 외 변경도 포함되며, 수정 커밋 단독 revert 실험으로 인과를 확인하지는 않았다. 다만 S1/S2/S4가 두 버전에서 동일하고 S3에서만 갈린다.

## 6. 결론

[확실] 이 고정된 테스트베드에서 CVE-2026-2673 발현 조건과 수정 대조를 재현했다.

## 참고 자료

1. Rescorla, E., "The Transport Layer Security (TLS) Protocol Version 1.3", RFC 8446, August 2018. <https://www.rfc-editor.org/rfc/rfc8446.txt>
2. OpenSSL, `SSL_CTX_set1_curves(3)` manual page, OpenSSL 3.5. <https://docs.openssl.org/3.5/man3/SSL_CTX_set1_curves/>
3. OpenSSL Security Advisory [20260313], "OpenSSL TLS 1.3 server may choose unexpected key agreement group". <https://openssl-library.org/news/secadv/20260313.txt>
4. CVE Record, CVE-2026-2673. <https://www.cve.org/CVERecord?id=CVE-2026-2673>
5. OpenSSL fix commit (3.5), `85977e013f32ceb96aa034c0e741adddc1a05e34`, "Fix group tuple handling in DEFAULT expansion". <https://github.com/openssl/openssl/commit/85977e013f32ceb96aa034c0e741adddc1a05e34>
6. OpenSSL fix commit (3.6), `2157c9d81f7b0bd7dfa25b960e928ec28e8dd63f`. <https://github.com/openssl/openssl/commit/2157c9d81f7b0bd7dfa25b960e928ec28e8dd63f>
7. IETF TLS WG, "Terminology for Post-Quantum Traditional Hybrid Schemes", RFC 9954 (2026-09-28 기준 발행, Informational, 2026-07; 이전 draft-ietf-tls-hybrid-design). <https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/>
8. IETF TLS WG, "Hybrid key exchange in TLS 1.3 using X25519 and ML-KEM", RFC 10024 (2026-09-28 기준 발행, Proposed Standard, 2026-08; 이전 draft-ietf-tls-ecdhe-mlkem). <https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/>
9. Karthikeyan Bhargavan, Christina Brzuska, Cédric Fournet, Matthew Green, Markulf Kohlweiss, Santiago Zanella-Béguelin, "Downgrade Resilience in Key-Exchange Protocols", IEEE S&P 2016. <https://www.microsoft.com/en-us/research/publication/downgrade-resilience-in-key-exchange-protocols/>
10. 저장소 근거 대장, `docs/EVIDENCE.md`.

## 부록: AI-대-인간 책임 공개

[확실] v1.2에서 AI는 fault-injection 도구 확장(`tools/faultinject/v12.py`, `pcap_hello.py`, `audit.py`, `analyze.py --v12`), A-0 환경 조사 스크립트 실행, 60회 반복 실행 자동화, 원시 데이터 집계, RFC 8446·OpenSSL 문서 규범 분석 초안, 그리고 본 논문 초안 작성에 사용됐습니다.

[확실] 인간(저자)은 v1.2의 연구 질문과 CVE 재현 판정 규칙(설계 §2.2)을 결정하고, S1–S4 실험 행렬과 A-0 격리 조건을 설계했으며, 원시 데이터·PCAP·SHA-256·커밋 조상 관계와 최종 결론의 범위를 검토·확인했습니다.

[확실] 최종 검증은 원시 JSON 60건·PCAP·로그의 존재와 집계값, `python -m faultinject.analyze --v12` 출력과 논문 표의 일치, 테스트 결과, v1.2 재현 ZIP 검증을 함께 대조하는 방식으로 수행합니다.
