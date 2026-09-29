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

[불확실] 결과는 OpenSSL 3.5.5/3.5.6, client preference, loopback, 고정 명령과 조합별 10회에 한정됩니다. 다른 배포·구성, 실배포 공격 가능성 또는 수정 커밋 단독의 인과를 일반화하지 않습니다.

## 공식 참고 자료

1. [RFC 8446, TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html)
2. [OpenSSL 3.5 `SSL_CTX_set1_curves(3)`](https://docs.openssl.org/3.5/man3/SSL_CTX_set1_curves/)
3. [OpenSSL Security Advisory 20260313](https://openssl-library.org/news/secadv/20260313.txt)
4. [CVE-2026-2673 record](https://www.cve.org/CVERecord?id=CVE-2026-2673)
5. [OpenSSL 3.5 fix commit `85977e0`](https://github.com/openssl/openssl/commit/85977e013f32ceb96aa034c0e741adddc1a05e34)
