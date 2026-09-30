# 하이브리드 PQ 키 교환의 협상 함수: 실제 클라이언트와 서버 정책의 관측

- 저자: whiteclover0542
- 문서 갱신: 2026-09-30
- 데이터: 정식 실험 726회(기존 687회와 실제 기본 클라이언트 확대 24회, Botan C3 서버유형 대조 15회)와 보조 표본 20회

## 초록

하이브리드 키 교환의 다운그레이드 저항성은 공격자가 정상 협상 결과를 약하게 바꾸지 못함을 보장하지만, 그 정상 결과가 하이브리드인지는 보장하지 않는다. 본 연구는 이 결과를 정하는 규칙을 **협상 함수**라 부르고, 공격자 조작에 의한 **다운그레이드**, 하이브리드를 선호한 C2 클라이언트 또는 서버 정책 불일치에서 생기는 **PQ 누락**, 그리고 클라이언트가 고전을 먼저 선호한 **클라이언트 선호 고전 협상**을 구분한다. 하이브리드 우선으로 설정한 다섯 TLS 서버(OpenSSL, BoringSSL, Go, NSS, rustls)는 key-share 우선·클라이언트 순서·서버 순서의 세 유형으로 갈렸다. key-share 우선 유형(OpenSSL 단일 tuple, NSS)은 C2에 HRR 없이 고전을 주었고, OpenSSL CVE-2026-2673은 `DEFAULT` 확장 경로의 `ssl/t1_lib.c` 수정만 넣고 빼는 3.5·3.6 인과 분리로 재현했다. 실제 기본값 8개를 더 조사했지만 C2는 없었고, Botan C3은 서버 선택 유형에 따라 고전 또는 HRR 뒤 하이브리드가 관측됐다. 경로상 조작 60회는 모두 연결 실패였고, 측정한 기본·상세 도구 출력에는 자동 경고가 없었다. 따라서 확정된 결함은 OpenSSL 하나이지만, 실제 PQ 적용이 구현별 협상 함수와 클라이언트 key share 전략에 달린다는 구조는 시험한 다섯 TLS 구현에서 관측됐다.

## 1. 서론

하이브리드 키 교환은 고전 알고리즘과 PQ 알고리즘을 함께 써서, 둘 중 하나만 안전해도 세션 키가 보호되게 하는 전환기 방식이다 [2, 3]. 다운그레이드 저항성, 즉 공격자가 양쪽이 정상적으로 협상했을 방식보다 약한 방식을 강제하지 못한다는 성질은 설계 수준에서 형식화되어 있다 [9]. 하이브리드 결합이 핸드셰이크 transcript에 묶여 있으면 다운그레이드를 막는다는 증명도 프리프린트로 제시되었다 [10]. 이런 결과 때문에 운영자는 표준 하이브리드 구성을 켜면 PQ 보호가 적용된다고 가정하기 쉽다.

그러나 다운그레이드 저항성의 기준은 공격자가 없을 때 양쪽이 정상적으로 협상했을 결과이다 [9]. 증명은 공격자가 그 결과를 약하게 바꿀 수 없다는 것을 보장할 뿐, 그 결과가 하이브리드인지는 말하지 않는다. 그 결과는 클라이언트가 무엇을 광고하고 어떤 key share를 먼저 보내는지, 서버가 어떤 규칙으로 그룹을 고르는지에 달려 있다. 2026년 3월 공개된 OpenSSL CVE-2026-2673 [5, 6]은 이 선택 과정의 결함만으로, 공격자 없이 하이브리드가 조용히 고전 그룹으로 바뀔 수 있음을 보여 주었다.

본 연구는 이 간극을 여섯 구현에서 측정한다. 연구 질문은 기획 단계의 것을 그대로 둔다.

- **RQ1.** 경로상 공격자가 협상을 조작할 때, 실제 구현은 증명이 보장하는 대로 다운그레이드를 막는가?
- **RQ2.** 공격자가 없을 때, 하이브리드를 지원하는 클라이언트와 서버 사이에서 하이브리드가 조용히 빠질 수 있는가? 그 사실이 표준 감사 출력에 드러나는가?
- **RQ3.** 협상 로직의 결함이 하이브리드 PQ 다운그레이드로 이어지는 것은 특정 라이브러리의 우연한 버그인가, 여러 구현체에 걸친 일반적 패턴인가?

RQ3의 "다운그레이드"는 기획 단계의 표현이며, 본 논문의 용어로는 PQ 누락에 해당한다(§2.1).

RQ2의 "표준 감사 출력"은 본 논문에서 측정한 기본·상세 도구 출력으로 한정한다(§5.3, §6.5).

본 연구의 기여는 다음과 같다.

1. 다섯 TLS 서버 구현의 협상 함수를 같은 조건에서 비교해, 하이브리드 우선 설정에서도 key share 우선, 클라이언트 순서, 서버 순서의 세 선택 유형이 있음을 보이고, 문서가 없는 두 구현(BoringSSL, NSS)의 유형을 소스 코드로 확인했다(§6.1).
2. 기본 설정의 클라이언트 여섯 개, headless 브라우저 두 개, 서버 패키지 두 개(nginx, Caddy)로 C2형 PQ 누락 조건이 기본값에서 성립하는지 조사했다(§6.2).
3. 서버가 자기 정책을 지키지 못한 OpenSSL 결함(CVE-2026-2673)을 재현하고, 수정 코드를 넣고 빼는 인과 분리로 3.5와 3.6 두 계열에서 확정했다(§6.3).
4. 세 구현 × 경로상 결함 유형의 비교표를 제시하고, 각 거부가 어느 방어 계층(transcript 결합, 교환 해시 서명, 키 형식 검증)에서 일어났는지 구분했다(§6.4).
5. 측정한 TLS 기본 감사 출력이 C2형 PQ 누락과 CVE 정책 불일치를 경고하거나 드러내지 않고, 상세 출력은 판단 재료를 보여 주지만 경고하지 않음을 보였다(§6.5).

## 2. 배경

### 2.1 용어: 협상 함수, 다운그레이드, PQ 누락

본 논문에서 **협상 함수**는 양쪽의 설정과 구현이 주어졌을 때, 공격자 없이 어떤 그룹이 협상되는지를 정하는 규칙이다. **다운그레이드**는 공격자가 메시지를 조작해 협상 함수의 결과보다 약한 방식을 강제하는 것이다 [9]. **PQ 누락**은 공격자 없이 고전 그룹이 선택됐지만, (a) 클라이언트가 하이브리드를 고전보다 선호하면서 초기 key share만 미룬 C2이거나, (b) 서버가 문서화하거나 설정한 하이브리드 우선 정책과 다르게 고전을 선택한 경우다. 전자는 구현이 문서나 소스에 명시한 규칙대로의 동작일 수 있고(§6.1), 후자는 구현이 자기 정책을 어긴 결함일 수 있다(§6.3). **클라이언트 선호 고전 협상**은 C3·E4처럼 클라이언트가 고전을 먼저 선호해 고전이 선택된 경우다. 이는 하이브리드를 지원하더라도 PQ 누락이나 다운그레이드가 아닌 정상 협상으로 분류한다. 한쪽이 하이브리드를 지원하지 않거나 기본 설정에서 하이브리드를 광고·선택하지 않아 양쪽이 하이브리드를 쓰는 조건 자체가 성립하지 않는 경우는 **PQ 미적용**이라 부른다(§6.2, §6.2.1).

### 2.2 TLS 1.3과 SSH의 키 교환 협상

TLS 1.3 클라이언트는 `supported_groups`로 지원 그룹을 광고하고, `key_share`로 그중 일부의 키 재료를 미리 보낸다 [1]. 서버는 그룹을 고른다. 고른 그룹의 key share가 이미 와 있으면 ServerHello로 응답하고, 서로 지원하지만 key share가 없으면 HRR로 다시 요청한다. RFC 8446은 호환되는 key share가 없을 때 HRR을 보내도록 요구하지만, 호환되는 key share가 이미 있을 때 더 선호하는 그룹을 위해 HRR을 보내라고 요구하지는 않으며, 그룹 선택 기준을 구현에 맡긴다. 핸드셰이크 키는 지금까지의 메시지 전체(transcript)로부터 유도되므로, 전송 중 메시지를 바꾸면 양쪽의 키가 달라져 연결이 실패한다. HRR은 ServerHello와 같은 형식을 쓰고, 고정된 random 값으로만 구분된다.

SSH는 양쪽이 보낸 KEX 알고리즘 목록에서 클라이언트 목록 순서상 처음으로 겹치는 알고리즘을 고른다 [13]. 선택 규칙이 규격에 고정되어 있다는 점이 TLS와 다르다. 서버는 키 교환 결과와 양쪽 협상 메시지를 포함한 교환 해시에 호스트 키로 서명한다.

### 2.3 하이브리드 그룹

`X25519MLKEM768`은 ML-KEM-768과 X25519를 결합한 TLS 하이브리드 그룹이다 [3]. 두 성분의 공개값과 공유 비밀을 연결해 키 스케줄에 넣는다 [2]. 하이브리드 key share는 고전 key share보다 훨씬 크다. 그래서 클라이언트는 초기 key share로 고전 그룹만 보내고, 하이브리드는 서버가 요청할 때 보내는 전략을 쓸 수 있다. 권고문은 이런 클라이언트를 CVE-2026-2673의 발현 조건으로 든다 [5].

### 2.4 OpenSSL 3.5의 그룹 tuple과 `DEFAULT`

OpenSSL 3.5의 서버 그룹 목록에서 `:`는 같은 우선순위 묶음(tuple) 안의 그룹을, `/`는 tuple 경계를 구분한다 [4]. 서버는 선호도가 높은 tuple부터 살핀다. 현재 tuple 안에 이미 받은 key share가 있으면 ServerHello로, 지원 그룹만 있으면 HRR로 응답한다. 내장 기본 목록은 하이브리드 그룹을 별도의 첫 tuple로 둔다. CVE-2026-2673은 설정 문자열 안의 `DEFAULT` 키워드를 확장할 때 이 tuple 경계가 사라지는 결함이다 [5, 7, 8].

## 3. 관련 연구

Bhargavan 등은 설정 가능한 키 교환 프로토콜의 다운그레이드를 형식화하고, 다운그레이드 저항성의 조건을 분석했다 [9]. Gupta와 Rana는 하이브리드 PQ 키 설정에서 transcript에 결합된 combiner가 다운그레이드를 막는다는 증명을 프리프린트로 제시했다 [10]. FREAK은 TLS 상태 기계의 구현 결함이 [11], Logjam은 수출 등급 Diffie-Hellman 지원이라는 프로토콜 수준의 약점이 [12] 실제 다운그레이드 공격으로 이어진 사례이다. 이들 연구는 경로상 공격자가 협상을 조작하는 경우를 다룬다. 본 연구는 같은 경우를 실제 PQ 하이브리드 구현에서 측정하고(RQ1), 여기에 더해 증명의 기준인 협상 함수 자체를 구현에서 측정한다(RQ2, RQ3). 이는 증명과 충돌하지 않으며, 증명이 전제로 두는 부분을 들여다보는 것이다.

배포와 규격 쪽 자료도 같은 지점을 다룬다. Benjamin의 key share 예측 초안은 클라이언트가 `supported_groups` 중 일부에만 key share를 보내므로 나머지 그룹에는 HRR이 필요하고, PQ KEM은 키가 커서 이 비용이 두드러진다고 설명한다 [21]. 이 초안의 보안 고려 사항은 서버가 그룹을 고를 때 서버 선호, 클라이언트 선호, key share 유무를 볼 수 있다고 정리한 뒤, key share 유무는 두 그룹의 선호가 비슷할 때만 기준으로 삼아야 하며 "서버는 key_share를 이유로 PQ 그룹 대신 고전 그룹을 골라서는 안 된다(SHOULD NOT)"고 권고한다 [21, 4절]. 이 초안은 2026년 9월 만료된 Internet-Draft로 규범이 아니다. Wickramasinghe 등은 상위 100만 도메인 중 세 차례 측정 모두 모든 관측 지점에서 TLS 1.3에 성공한 684,494개 도메인을 추적해, 모든 그룹을 광고하는 핸드셰이크에서 `X25519MLKEM768`이 기본으로 협상된 비율이 2025년 7월 31.26%, 2026년 3월 49.22%였다고 보고했다 [22]. 같은 표에서 명시적으로 요청했을 때 협상된 비율(지원)은 기본 협상 비율과 거의 같았다(2026년 3월 차이 2개 도메인). Cloudflare는 2025년 10월 블로그에서 origin 서버 연결에 PQ key share를 즉시 보내는 방식과 HRR 한 번만큼 미루는 방식을 나누고, 뒤의 방식을 비엔터프라이즈 고객의 기본값으로 켰다고 밝혔다 [23]. 본 논문은 이 자료들을 측정의 맥락으로만 인용하며, 그 수치를 다시 측정하지 않았다.

## 4. 위협 모델

- **영역 A: 경로상 조작(다운그레이드).** 공격자는 클라이언트와 서버 사이에서 핸드셰이크 메시지를 수정할 수 있지만, 서버의 장기 키는 없다. 성공한 다운그레이드란 공격자가 없었다면 하이브리드로 협상되었을 연결이 고전 그룹으로 성공하는 것이다. 형식 증명이 보장하는 성질을 시험한다.
- **영역 B: 공격자 없는 협상.** 정상 클라이언트와 정상 설정의 서버가 협상한다. 협상 함수와 C2형 PQ 누락, 클라이언트 선호 고전 협상을 구분해 측정한다.

범위는 로컬 loopback의 고정 테스트베드이다. 인터넷 규모의 배포 빈도는 측정하지 않으며, 브라우저는 headless 빌드 두 개의 기본 ClientHello만 조사한다.

## 5. 방법

### 5.1 테스트베드

모든 실험은 WSL Ubuntu의 loopback에서 수행했다. 협상 함수 비교(E8)에는 OpenSSL 3.5.6, BoringSSL(2024-08 빌드 `7fb4d3d`, `X25519MLKEM768` 사용), Go 1.26 `crypto/tls`로 작성한 최소 서버, NSS 3.120 `selfserv`, rustls 0.23.45(aws-lc-rs)로 작성한 최소 서버를 썼다. 기본값 조사(E9)에는 소스 빌드 OpenSSL 3.5.5 `s_client`, BoringSSL `bssl client`(같은 2024-08 빌드), Ubuntu 패키지(curl 8.18.0과 시스템 OpenSSL 3.5.5-1ubuntu3.5, NSS 3.120 `tstclnt`, nginx 1.28.3, Caddy 2.6.2), Go·rustls 최소 클라이언트를 썼다. 브라우저 조사(E10)에는 Chrome for Testing 154.0.8037.57의 `chrome-headless-shell`과 Firefox 156.0.1 공식 배포판을 headless로 썼다. CVE 사례(E5–E7)는 OpenSSL 3.5.5, 3.5.6, 3.6.1, 3.6.2와 네 패치 변형의 소스 빌드를, 경로상 조작(E1–E3)은 OpenSSL 3.5.5(oqs-provider 0.9.0), BoringSSL, OpenSSH portable의 고정 빌드를 썼다. 동작이 결정적이므로 E1–E7은 10회, E8은 5회, E9·E10과 `-trace` 재실행은 3회 반복했다.

### 5.2 실험

**표 1.** 공격자 없는 TLS 협상에서의 클라이언트 유형

| 유형 | `supported_groups` 선호 | 초기 `key_share` | 본문의 분류 |
|---|---|---|---|
| C1 | 하이브리드 1순위 | 하이브리드 포함 | 하이브리드 협상 기준선 |
| C2 | 하이브리드 1순위 | 고전만 포함 | C2형 PQ 누락 조건 |
| C3 | 고전 1순위 | 고전만 포함 | 클라이언트 선호 고전 협상 |

본문은 위 유형과 결과 흐름만 제시하며, E1–E11의 전체 실험 행렬은 부록 C에 둔다. C2는 OpenSSL의 `X25519MLKEM768:*X25519` 설정으로 만들었다(`*`는 key share를 보낼 그룹 표시). 모든 서버는 각 구현의 기본 선택 모드로 동작했고, OpenSSL은 서버 선호 옵션(`-serverpref`)을 켠 조건을 따로 시험했다. 보조 조건으로 OpenSSL 서버 그룹 설정을 생략한 S4를 실행했다.

### 5.3 측정

각 실행은 협상된 그룹, 핸드셰이크 성공 여부와 실패 원인, 패킷 캡처를 남긴다. HRR은 캡처된 ServerHello의 random이 RFC 8446의 HRR 고정값과 같은지로 판정했다. 클라이언트 전제(광고 순서와 key share)는 매 실행 캡처로 검증했다. 조작 실험은 프록시 로그와 캡처로 조작이 실제 적용되었음을 확인했다. E5의 재현 판정 규칙은 수집 전에 코드로 고정했다. S3에서 영향 버전은 HRR 없이 `X25519`, 수정 버전은 HRR 뒤 `X25519MLKEM768`로 협상해야 하고, S1과 S2는 문서화된 결과를 보여야 하며, 각 조합은 10회 일관되어야 한다. 로그와 캡처의 HRR 판정 일치, 실제 ServerHello 1개 조건은 수집 뒤 규칙을 강화하며 추가했다(판정 결과는 같음). E9a는 ClientHello와 서버가 고른 그룹만 기록했고, 클라이언트별 핸드셰이크 완료는 판정하지 않았다(원시 기록의 `handshake_result`는 OpenSSL 외 클라이언트에서 출력 형식 차이로 `failure`로 남아 있다). Caddy 2.11.4 대조는 E9a·E9b를 다시 실행한 36회 중 Caddy C1–C3 9회이며, 기본 클라이언트를 최신 Caddy에 직접 연결하지는 않았다. 감사 가시성은 클라이언트 로그, 서버 로그, 캡처 기본 요약의 세 경로에서, 명시적 경고 문구가 있는지와 한 출력 안에서 광고 그룹과 협상 그룹을 함께 식별할 수 있는지로 측정했다. 상세 출력은 두 경로를 추가로 같은 기준으로 측정했다. 보존된 캡처 537개(E5–E10, 인과 분리, 최신 대조)에 `tshark -V`를 적용했고, E5의 세 조건(3.5.5 S1·S3, 3.5.6 S3)을 클라이언트 `s_client -trace`로 3회씩 다시 실행했다. 상세 출력의 경고는 경고 문구와, 연결 순서(Sequence) 항목을 제외한 tshark 전문가 정보(Warning·Error)로 판정했다.

## 6. 결과

### 6.1 다섯 TLS 구현의 협상 함수(E8)

표 2는 같은 고정 클라이언트를 다섯 TLS 서버 구현에 연결한 105회의 결과이다. 모든 서버는 설정에서 하이브리드를 고전보다 먼저 나열했다. 105회 모두 클라이언트 전제가 캡처로 확인됐고, 핸드셰이크가 완료됐으며, 각 조합의 5회는 모두 같은 결과였다.

**표 2.** 다섯 TLS 서버 구현의 협상 함수(각 5회; `HRR→하이브리드`는 HRR 뒤 `X25519MLKEM768`)

| 서버 | 선택 유형 | C1 하이브리드 1순위 + 하이브리드 share | C2 하이브리드 1순위 + `X25519` share만 | C3 고전 1순위 + `X25519` share |
|---|---|---|---|---|
| OpenSSL 3.5.6, 단일 tuple `X25519MLKEM768:X25519` | key share 우선 | 하이브리드 | **고전(HRR 없음)** | 고전 |
| OpenSSL 3.5.6, 단일 tuple + `-serverpref` | key share 우선 | 하이브리드 | **고전(HRR 없음)** | 고전 |
| NSS 3.120 `selfserv` | key share 우선 | 하이브리드 | **고전(HRR 없음)** | 고전 |
| BoringSSL `bssl server` | 클라이언트 순서 | 하이브리드 | HRR→하이브리드 | 고전 |
| rustls 0.23.45 | 클라이언트 순서 | 하이브리드 | HRR→하이브리드 | 고전 |
| Go 1.26 `crypto/tls` | 서버 순서 | 하이브리드 | HRR→하이브리드 | **HRR→하이브리드** |
| OpenSSL 3.5.6, tuple 경계 `X25519MLKEM768/X25519` | 서버 순서 | 하이브리드 | HRR→하이브리드 | **HRR→하이브리드** |

서버 설정이 같아도 결과는 구현에 따라 달랐다. **key share 우선** 유형은 이미 받은 key share로 협상할 수 있으면 HRR을 보내지 않는다. 그래서 하이브리드를 1순위로 원하면서 key share만 미룬 C2가 고전 그룹을 받았다. 양쪽이 하이브리드를 지원하고 클라이언트도 하이브리드를 선호하는데 고전이 협상되었으므로, 이는 C2형 PQ 누락이다. OpenSSL에서는 서버 선호 옵션을 켜도 같았다. **클라이언트 순서** 유형은 클라이언트가 광고한 순서를 따르고, 그 그룹의 key share가 없으면 HRR로 요청한다. C3의 고전 결과는 클라이언트 선호 고전 협상이다. **서버 순서** 유형은 서버의 선호를 따르므로, 고전을 1순위로 광고한 C3에도 하이브리드를 협상했다.

관측한 유형을 각 구현의 문서나 소스와 대조했다. OpenSSL의 결과는 문서화된 선택 의사코드와 일치했다 [4]. Go 문서는 "CurvePreferences 목록의 순서는 무시되고, 내부 선호 순서로 선택한다"고 밝히며 [14], 관측은 하이브리드를 우선하는 내부 선호와 일치했다. rustls 문서는 그룹 목록을 "선호 순서"라고만 적고 서버 쪽 선택 규칙은 적지 않는다 [15]. 공개 문서에서 선택 규칙을 찾지 못한 BoringSSL과 NSS는 소스 코드를 확인했다.

- **BoringSSL**(2024-08 commit `7fb4d3d`, 최신 대조 commit `697ee71`): `tls1_get_shared_group`(`ssl/extensions.cc` 323–360행)은 `SSL_OP_CIPHER_SERVER_PREFERENCE`가 없으면 클라이언트의 `supported_groups` 순서를 선호 순서로 삼아 처음 겹치는 그룹을 고른다 [16]. 서버는 이 함수로 그룹을 먼저 정한 뒤(`ssl/tls13_server.cc` 471행), 그 그룹의 key share가 없으면 HRR을 보낸다(같은 파일 478–479행, 581–586행). 최신 대조의 C1–C3 각 3회도 2024-08 빌드와 같은 결과여서, 두 시험 시점 모두 클라이언트 순서 유형과 일치한다.
- **NSS**(3.120 릴리스 태그): `tls13_NegotiateKeyExchange`(`lib/ssl/tls13con.c`)는 서버 선호 목록의 첫 그룹을 선호 그룹으로 정하고, 그 그룹의 key share가 없으면 다음 그룹의 key share를 본다. 그 그룹이 `tls13_isGroupAcceptable`, 즉 선호 그룹과 강도(비트 수)가 ±2비트 이내이면 HRR 없이 그 그룹을 택한다(2016–2033행, 2091–2128행) [17]. `lib/ssl/sslsock.c`는 `X25519MLKEM768`과 X25519를 모두 256비트로 정의한다(170–171행). 따라서 NSS는 하이브리드 대신 X25519를 받아들일 수 있는 대체재로 판단한다. 이 강도 비교에는 PQ 여부가 들어가지 않는다. 관측된 key share 우선 유형은 이 규칙의 결과이다.

### 6.2 기본 설정의 클라이언트와 실제 서버(E9)

§6.1의 C2형 PQ 누락은 하이브리드를 선호하면서 key share를 미루는 클라이언트에서 나타났다. E9a는 기본 설정의 클라이언트가 이 조건에 해당하는지 조사했다(표 3, 18회).

**표 3.** 기본 설정 클라이언트의 ClientHello(각 3회, 모두 같은 결과; 서버는 OpenSSL 3.5.6 기본 설정)

| 클라이언트 | `supported_groups` 앞부분 | 초기 `key_share` | 협상 그룹 |
|---|---|---|---|
| OpenSSL 3.5.5 `s_client` | `X25519MLKEM768`, `X25519`, … | `X25519MLKEM768`, `X25519` | `X25519MLKEM768` |
| curl 8.18.0(시스템 OpenSSL 3.5.5) | `X25519MLKEM768`, `X25519`, … | `X25519MLKEM768`, `X25519` | `X25519MLKEM768` |
| Go 1.26 `crypto/tls` | `X25519MLKEM768`, `X25519`, … | `X25519MLKEM768`, `X25519` | `X25519MLKEM768` |
| rustls 0.23.45 | `X25519MLKEM768`, `X25519`, … | `X25519MLKEM768`, `X25519` | `X25519MLKEM768` |
| NSS 3.120 `tstclnt` | `X25519MLKEM768`, `X25519`, … | `X25519MLKEM768` | `X25519MLKEM768` |
| BoringSSL `bssl client`(2024-08 빌드) | `X25519`, P-256, P-384 | `X25519` | `X25519` |

하이브리드를 광고한 다섯 클라이언트는 모두 첫 ClientHello에 하이브리드 key share를 함께 보냈다. 즉 기본 설정에서는 C1에 해당했고, E8에서 C1은 다섯 서버 모두에서 하이브리드를 받았다. 시험한 기본 클라이언트 중 PQ 누락 조건(C2)에 해당하는 것은 없었다. 2024-08 BoringSSL 빌드는 기본값으로 하이브리드를 광고하지 않았다. 이는 해당 빌드의 기본값이며, 현재 BoringSSL의 기본값은 측정하지 않았다.

E10에서 두 브라우저도 같은 결과였다(각 3/3회). headless Chrome 154는 GREASE 값 [20], `X25519MLKEM768`, `X25519`, P-256, P-384 순으로 광고하고 GREASE·`X25519MLKEM768`·`X25519` key share를 보냈다. Firefox 156은 `X25519MLKEM768`, `X25519`, P-256, P-384, P-521 순으로 광고하고 `X25519MLKEM768`·`X25519`·P-256 key share를 보냈다. 두 브라우저 모두 C1에 해당했고, 서버는 HRR 없이 하이브리드를 협상했다. 시험한 브라우저는 headless 빌드이며, 일반 배포판이나 모바일 빌드의 설정은 확인하지 않았다.

E9b는 서버 패키지를 기본 설정으로 띄우고, E8과 같은 고정 클라이언트 C1–C3로 연결했다(표 4, 18회). 18회 모두 클라이언트 전제가 캡처로 확인됐고 핸드셰이크에 성공했다.

**표 4.** 기본 설정 서버 소프트웨어(각 3회, 모두 같은 결과)

| 서버 | C1 하이브리드 1순위 + 하이브리드 share | C2 하이브리드 1순위 + `X25519` share만 | C3 고전 1순위 + `X25519` share |
|---|---|---|---|
| nginx 1.28.3(시스템 OpenSSL 3.5.5) | 하이브리드(HRR 없음) | HRR→하이브리드 | HRR→하이브리드 |
| Caddy 2.6.2 | **HRR→`X25519`** | 고전(HRR 없음) | 고전(HRR 없음) |

nginx는 그룹 설정이 없으면 OpenSSL의 내장 기본 목록을 쓰며, 이 목록은 하이브리드를 별도의 첫 tuple로 둔다(§2.4). 그래서 서버 순서 유형으로 동작해 C3에게까지 하이브리드를 협상했다. C3의 대조 결과는 서버 선호 하이브리드 협상으로 끝났고, 기본 설정의 nginx에서는 C2형 PQ 누락이 없었다. Caddy 2.6.2는 하이브리드 key share만 보낸 C1에게 HRR로 X25519 key share를 요청했고, 세 클라이언트 모두 고전으로 협상했다. 이 버전은 기본 설정에서 하이브리드를 고르지 않았다. `go version -m` 출력에는 Go 1.25.0의 `tlsmlkem=0`이 남아 있다. 이 동작은 협상 함수가 하이브리드를 다른 그룹과 비교한 결과가 아니므로, 본 논문의 용어로는 PQ 누락이 아니라 PQ 미적용이다.

E9c는 기본 설정 클라이언트와 기본 설정 서버를 직접 연결한 36회이다(표 5). nginx는 BoringSSL에 X25519, 나머지 다섯 클라이언트에 하이브리드를 협상했다. Caddy 2.6.2는 BoringSSL·OpenSSL·curl·Go·NSS에 X25519를 협상했다. rustls–Caddy 세 연결은 ServerHello 없이 실패했으며, 클라이언트·서버 로그에는 원인을 식별할 오류가 없어 SNI·인증서·ALPN 원인을 주장하지 않는다.

**표 5.** 기본 클라이언트 × 기본 서버 직접 연결(각 3회)

| 서버 | X25519 | `X25519MLKEM768` | 실패 |
|---|---:|---:|---:|
| nginx 1.28.3 | BoringSSL 3/3 | OpenSSL·curl·Go·NSS·rustls 각 3/3 | 0/18 |
| Caddy 2.6.2 | BoringSSL·OpenSSL·curl·Go·NSS 각 3/3 | 0/18 | rustls 3/3 |

공식 Caddy 2.11.4(Go 1.26.3) 대조에서 고정 C1은 HRR 없이, C2·C3는 HRR 뒤 하이브리드를 각각 3/3회 협상했다. Caddy 2.6.2와 2.11.4는 Caddy와 Go 버전이 함께 달라지므로, `tlsmlkem=0`이 차이의 유일한 원인이라는 인과 주장은 하지 않는다. 다만 Caddy 2.6.2의 내장 Go 기본값과 최신 대조 결과는 Go TLS ML-KEM 기본값 설명과 일치한다 [18, 19].

### 6.2.1 실제 기본값 확대와 Botan C3 정책 대조(E11)

E11은 기본 설정을 더 넓게 확인하되, 후보의 그룹 순서나 key share를 바꾸지 않았다. 표 6의 24회(후보 8개 × 3회)에서 C2, 즉 **하이브리드 1순위인데 하이브리드 key share를 보내지 않는** 기본 클라이언트는 없었다. wolfSSL, s2n-tls, Node.js, Python은 C1이었다. GnuTLS, Java, mbedTLS는 하이브리드를 광고하지 않아 PQ 미적용으로 분류했다. Botan 3.10.0만 하이브리드를 3순위로 광고하면서 X25519 share만 보내는 C3이었다. 따라서 Botan은 C2가 아니며, 이 표본은 서버가 하이브리드 우선인 C2를 고전으로 바꾸는 사례가 아니다.

**표 6.** v1.8 실제 기본 클라이언트의 ClientHello(각 3회, OpenSSL 3.5.6 기본 서버)

| 분류 | 클라이언트 | `supported_groups`와 `key_share`의 관측 |
|---|---|---|
| C1 | wolfSSL, s2n-tls, Node.js, Python | 하이브리드를 첫 그룹·초기 share에 포함 |
| C3 | Botan 3.10.0 | `X25519`, P-256, `X25519MLKEM768`, … / `X25519` share만 |
| PQ 미적용 | GnuTLS, Java, mbedTLS | 기본 `supported_groups`에 하이브리드 없음 |

Botan C3의 서버유형 대조 15회는 key-share 우선(OpenSSL 단일 tuple 두 설정, NSS)과 클라이언트 순서(BoringSSL) 서버에서 HRR 없이 X25519가 각 3/3회임을 보였다. 기본값 조사에서 OpenSSL 3.5.6 기본 설정은 서버 순서 유형으로 HRR 뒤 `X25519MLKEM768`을 3/3회 협상했고, 15회 대조의 Go 서버도 같은 서버 순서 결과를 3/3회 보였다. 앞의 네 고전 결과는 클라이언트가 스스로 고전을 첫 순위에 둔 C3의 **클라이언트 선호 고전 협상**이다. 그러므로 이는 PQ 누락, 실제 C2 존재, 또는 서버 정책 무시를 보이지 않으며, 이 제한된 서버 표본에서 C3 결과가 선택 유형에 의존한다는 것만 보인다.

### 6.3 CVE-2026-2673 사례(E5–E7)

E5–E7은 OpenSSL 서버 설정의 비교 행렬이다. 이 중 영향 버전의 S3 `DEFAULT` 결과는 서버가 문서화한 tuple 정책을 지키지 못한 PQ 누락이며, S1·S2는 문서화된 대조 조건이다. 표 7에서 고전 우선 클라이언트(E5)와 C2(E7)는 같은 결과를 보였다. 각 60회에서 클라이언트 전제가 검증됐고 모두 핸드셰이크에 성공했다.

**표 7.** CVE-2026-2673 사례(각 셀은 E5 10회와 E7 10회에서 같은 결과)

| 서버 | S1 단일 tuple | S2 tuple 경계 | S3 `DEFAULT` |
|---|---|---|---|
| 3.5.5 (영향) | HRR 0 · `X25519` | HRR 10 · `X25519MLKEM768` | **HRR 0 · `X25519`** |
| 3.5.6 (수정) | HRR 0 · `X25519` | HRR 10 · `X25519MLKEM768` | **HRR 10 · `X25519MLKEM768`** |

두 버전은 S3에서만 갈렸다. 하이브리드를 첫 tuple로 두는 기본 목록이 보존된다면 S3에서도 S2처럼 HRR로 하이브리드를 요청해야 한다. 3.5.5는 그러지 않았다. 로그와 캡처의 HRR 판정은 모두 일치했고, 별도 캡처 분석 도구(tshark)로 두 표본을 교차 확인한 결과도 같았다. 사전에 정한 판정 조건을 모두 만족하므로, 이 테스트베드에서 CVE-2026-2673의 발현 조건과 수정 대조를 재현했다고 판정한다. 보조 조건 S4(설정 생략)에서는 두 버전 모두 10/10회 HRR 뒤 하이브리드로 협상했다. 결함은 기본 목록 자체가 아니라 `DEFAULT` 키워드의 확장 경로에서만 나타났다. 클라이언트의 광고 순서는 서버의 선택을 바꾸지 않았다. S1의 결과는 §6.1의 key share 우선 동작과 같다.

**인과 분리(E6).** 표 8은 수정 변경의 유무만 다른 서버들의 S3 결과이다. 180회(3.5 변형과 3.6 태그 120회, 3.6 변형 60회) 모두 전제가 검증됐고 핸드셰이크에 성공했다. S1과 S2는 여섯 서버 모두 표 7과 같았다.

**표 8.** 수정 변경 유무에 따른 S3 결과(각 10회)

| 서버 | 수정 변경 | HRR | 최종 그룹 |
|---|---|---:|---|
| 3.5.5-cherrypick (3.5.5 + 수정 변경) | 있음 | 10/10 | `X25519MLKEM768` |
| 3.5.6-revert (3.5.6 − 수정 변경) | 없음 | 0/10 | `X25519` |
| 3.6.1 | 없음 | 0/10 | `X25519` |
| 3.6.2 | 있음 | 10/10 | `X25519MLKEM768` |
| 3.6.1-cherrypick (3.6.1 + 3.6 수정 변경) | 있음 | 10/10 | `X25519MLKEM768` |
| 3.6.2-revert (3.6.2 − 3.6 수정 변경) | 없음 | 0/10 | `X25519` |

수정 변경을 넣으면 영향 버전이 수정 버전처럼, 빼면 수정 버전이 영향 버전처럼 동작했다. 3.6 계열에서도 수정 커밋 `2157c9d`의 `ssl/t1_lib.c` 변경만 3.6.1에 넣으면 수정 버전처럼, 3.6.2에서 빼면 영향 버전처럼 동작했다. 따라서 두 계열 모두에서 S3 차이는 각 수정 커밋의 이 파일 변경 하나로 설명된다.

### 6.4 경로상 조작과 기준선(E1–E4)

표 9는 세 구현 × 결함 유형 비교표이다. 기획 단계의 비교(E1, E2)에 v1.1의 E3, E4를 더했다.

**표 9.** 구현 × 결함 유형 결과(각 10회)

| 결함 유형 | OpenSSL | BoringSSL | OpenSSH |
|---|---|---|---|
| E1 고전 전용 제시(기준선) | 성공, `X25519` | 성공, `X25519` | 성공, `curve25519-sha256` |
| E2 PQ 성분 변조(A) | 실패 10/10 — 키 형식 검증 | 실패 10/10 — 키 형식 검증 | 실패 10/10 — 교환 해시 서명 |
| E3 하이브리드 제거(A) | 실패 10/10 — transcript 결합 | 실패 10/10 — transcript 결합 | 실패 10/10 — 패킷 형식 오류(판정 불가) |
| E4 고전 우선 광고(B) | 성공, `X25519`, HRR 없음 | 성공, `X25519` | 시험 안 함(규격이 선택 규칙 고정) |

하이브리드를 우선 광고한 기본 협상은 세 구현 모두 하이브리드로 성공했다(OpenSSL `X25519MLKEM768`, BoringSSL `X25519Kyber768Draft00`, OpenSSH `sntrup761x25519-sha512`, 각 10/10). 이 단계의 BoringSSL 실험은 하네스 설정에서 이전 하이브리드 그룹 `X25519Kyber768Draft00`을 썼다(같은 빌드가 E8에서는 `X25519MLKEM768`을 협상했다).

E2와 E3의 60회에서 다운그레이드가 성공한 경우는 없었다. TLS의 하이브리드 제거는 두 구현 모두 transcript 결합이 막았다. OpenSSL은 HRR 뒤 `bad record mac`으로, BoringSSL은 남은 `X25519` key share로 응답한 뒤 복호화 실패로 끝났다. SSH의 PQ 성분 변조는 교환 해시 서명 검증 실패(`incorrect signature`)로 막혔다. 결합 계층이 직접 작동한 이 30회는 증명의 예측과 일치한다. 반면 TLS의 PQ 성분 변조는 결합 검증 이전에, 변조된 값이 유효한 PQ 공개키가 아니라는 키 형식 검증에서 거부되었다. 따라서 TLS 컴바이너 결합 자체는 시험되지 않았다. SSH의 KEX 제거는 패킷 길이가 블록 정렬을 벗어나 형식 오류로 끝나, 협상 방어를 판정하지 못했다. E4는 공격자 없는 클라이언트 선호 고전 협상으로, 클라이언트 스스로 고전을 우선했으므로 고전 협상은 규격과 각 구현 정책대로의 동작이다.

### 6.5 감사 가시성

v1.1 교차 구현 관측 90회, E5 60회, E7 60회에서 측정한 세 경로 어디에도 명시적 경고는 없었다. TLS 연결에서는 광고 그룹과 협상 그룹을 한 출력 안에서 함께 식별할 수 없었다. OpenSSL 클라이언트 로그는 협상 그룹을 이름으로 보여 주지만 광고 목록은 16진 덤프로만 남기고, BoringSSL 클라이언트 로그는 광고 목록을 남기지 않으며, 캡처 기본 요약에는 그룹 정보가 없다. 한 출력에서 둘을 함께 볼 수 있었던 것은 OpenSSH 상세 로그(30건)뿐이다. CVE 결함이 발현된 연결은 측정한 기본 출력에서 정상적인 고전 연결과 구별되지 않았다. 결함과 S1의 정상 동작은 전송되는 메시지가 같으므로, 협상 결과만으로 둘을 구분할 수 없는 것은 원리적으로도 예상되는 결과이다. E8–E10의 기본 출력 경로는 측정하지 않았다.

상세 출력은 달랐다. E5–E10과 인과 분리·최신 대조의 보존 캡처 537개에 `tshark -V`를 적용하면, ServerHello가 있는 534개 모두에서 ClientHello의 광고 그룹과 ServerHello의 key share 그룹이 한 출력에 나타났고, 그 그룹은 캡처 분석으로 기록한 협상 그룹과 모두 일치했다. 나머지 3개는 ServerHello 없이 끝난 rustls–Caddy 2.6.2 연결이다. `s_client -trace`로 다시 실행한 9회도 광고 그룹, 양쪽 key share, 협상 그룹을 이름으로 보여 주었다. 또 OpenSSL 서버는 협상한 그룹이 자기 1순위가 아닐 때만 EncryptedExtensions에 자기 지원 그룹 목록을 보낸다(3.5.6 소스 `ssl/statem/extensions_srvr.c` 1667–1699행). 그래서 3.5.5의 S1과 S3 연결 로그에는 서버가 `X25519MLKEM768`을 1순위로 둔 목록이 함께 찍혔고, 하이브리드를 협상한 3.5.6 S3에는 없었다. 이 목록은 암호화된 메시지에 있어 키 없이는 캡처로 볼 수 없다. 두 상세 출력 어디에도 경고는 없었다. 즉 상세 출력은 누락을 판단할 재료를 한곳에 모아 주지만, 판단은 사람이나 별도 도구가 광고 목록과 협상 결과를 비교해야 한다. 이 신호는 S1의 문서화된 동작과 S3의 결함을 구분하지 않는다.

## 7. 논의

표 10은 이 연구가 보인 것과 보이지 않은 것을 정리한다.

**표 10.** 이 연구가 보인 것과 보이지 않은 것

| 항목 | 보인 것 | 보이지 않은 것·범위 |
|---|---|---|
| OpenSSL 결함 | 3.5·3.6에서 `ssl/t1_lib.c` 수정만으로 CVE-2026-2673 S3 결과가 뒤집힘 | 실배포 구성의 영향 빈도 |
| TLS 협상 함수 | 하이브리드 우선 설정의 다섯 TLS 서버가 세 선택 유형으로 갈림 | 다른 버전·설정·구현의 보편적 정책 |
| 기본값·브라우저 | 시험한 기본 클라이언트 다섯 개와 headless Chrome·Firefox는 hybrid key share를 먼저 전송 | 일반 브라우저·모바일·인터넷 규모의 key share 분포 |
| v1.8 실제 기본값 | 8개 추가 표본에서 C2는 없고 Botan은 C3; 클라이언트 선호 고전 협상 결과는 다섯 서버의 선택 유형에 따라 갈림 | 실제 C2의 존재·빈도, 다른 버전·설정의 서버 정책 |
| 외부 자료 | 공개 자료상 대형 CDN이 2025년 10월 기준 비엔터프라이즈 고객의 origin 연결에 PQ key share를 HRR 뒤로 미루는 방식을 기본으로 켬 [23]; 인터넷 측정에서 `X25519MLKEM768` 지원 서버는 모든 그룹 광고 시 거의 모두 기본으로 그 그룹 선택 [22] | 그 CDN의 광고 순서와 origin 서버의 선택 유형, C2 연결의 실제 PQ 누락 비율 |
| Caddy | 배포판 Caddy 2.6.2가 직접 연결에서 다섯 클라이언트와 X25519를 협상 | `tlsmlkem=0`의 단일 인과, 최신 Caddy의 기본 클라이언트 직접 연결 |
| 경로상 조작 | 시험한 60회는 성공한 고전 협상으로 끝나지 않음; 결합 계층까지 도달한 30회(TLS 제거, SSH 변조)는 증명대로 막힘 | TLS 컴바이너 결합, SSH KEX 제거 방어 |
| 감사 가시성 | 측정한 기본·상세 도구 출력은 자동 경고하지 않음; 상세 출력은 판단 재료를 제공 | 다른 구현·서버 상세 출력·key log의 가시성 |

### 7.1 간극은 어디에 있는가(RQ1, RQ2)

증명이 보장하는 영역 A에서는 결합 계층까지 도달한 30회가 모두 막혀, 구현이 증명의 예측대로 동작했다(§6.4). 다만 하이브리드 컴바이너 결합 자체와 SSH의 KEX 목록 제거 방어는 판정하지 못했다.

간극은 영역 B에 있었다. 하이브리드를 지원하는 클라이언트와 서버가 만나도, 하이브리드가 쓰이는지는 협상 함수가 정했다. 증명은 협상 함수의 결과를 지킬 뿐이므로, 그 결과가 고전이면 고전을 지킨다. PQ 누락은 두 경로로 나타났다. 하나는 규격이 허용하고 구현이 문서나 소스에 명시한 선택 규칙의 결과로, key-share 우선 유형이 하이브리드를 선호하는 C2에게 고전을 준 경우다(§6.1). RFC 8446은 이미 호환되는 key share가 있을 때 HRR을 요구하지 않는다 [1]. 다른 하나는 구현이 자기 정책을 어긴 결함(CVE-2026-2673, §6.3)이다. C3·E4의 고전 결과는 별도의 클라이언트 선호 고전 협상이며 이 둘과 섞지 않는다. C2형 PQ 누락과 CVE 연결은 측정한 TLS 기본 출력에 드러나지 않았고, 상세 출력에서는 판단 재료만 보였을 뿐 경고는 없었다(§6.5). RQ2에 대한 답은 "그렇다, 그리고 기본 출력에는 드러나지 않았다"이다.

다만 기본값 조사(§6.2, §6.2.1)는 이 간극의 실제 발생 범위를 좁힌다. 기존 기본값·브라우저 표본에서 하이브리드를 광고한 다섯 클라이언트와 두 브라우저는 모두 하이브리드 key share를 먼저 보냈다. 추가한 v1.8 표본에서도 C2는 없었다. Botan은 C3이므로 서버 순서 유형에서는 HRR 뒤 하이브리드를, key-share 우선·클라이언트 순서 유형에서는 클라이언트 선호 고전 협상으로 고전을 받았다. CVE-2026-2673도 권고문의 설명대로 key share를 미루는 클라이언트에서만 발현된다 [5]. 직접 연결 표본에서 nginx는 기존 다섯 클라이언트에 하이브리드를 협상했고, Caddy 2.6.2는 다섯 클라이언트에 X25519를 협상해 PQ 미적용으로 관측됐다. 공개 자료는 이 범위 밖의 가능성을 보여 준다. Cloudflare는 2025년 10월 블로그에서 origin 서버 연결에 PQ key share를 즉시 보내는 방식과 HRR 한 번만큼 미루는 방식을 나누고, 뒤의 방식을 비엔터프라이즈 고객의 기본값으로 켰다고 밝혔다 [23]. 그 방식의 광고 순서는 공개되지 않아 본 논문의 C2와 같은지는 확인하지 못했다. 다만 PQ 그룹을 원하면서 key share를 미루는 클라이언트라면, 그 연결을 받는 key-share 우선 서버(OpenSSL 단일 tuple, NSS)나 CVE-2026-2673 영향 버전의 `DEFAULT` 설정 서버는 HRR 없이 고전 그룹을 고를 것으로 추론된다(§6.1, §6.3). key share를 미루는 하이브리드 우선 클라이언트가 실제로 얼마나 있고 어느 서버와 만나는지는 본 연구가 답하지 못한다.

### 7.2 우연한 버그인가, 일반적 패턴인가(RQ3)

결함 자체는 특정 라이브러리의 것이다. OpenSSL의 결과는 수정 커밋의 라이브러리 변경 하나로 켜지고 꺼졌고(§6.3), 커밋 제목("Fix group tuple handling in DEFAULT expansion")으로 보아도 `DEFAULT` 확장 경로의 결함이다. 다른 구현에는 tuple 구문이나 `DEFAULT`에 해당하는 설정 문법이 없어 같은 유형의 결함을 시험할 수 없었다.

그러나 결함이 들어간 틈은 구현 전반에 공통이었다. 다섯 TLS 서버 모두 하이브리드를 먼저 나열했지만 협상 함수는 세 유형으로 갈렸고, 두 구현(OpenSSL 단일 tuple, NSS)은 문서화되었거나 소스에 명시된 규칙대로 C2에게 고전을 주었다. NSS의 규칙은 강도를 비트 수로만 비교해 하이브리드와 X25519를 같은 것으로 보았다. 하이브리드 전환 이전에 만들어진 선택 규칙이 PQ 여부를 모르는 채 남아 있는 사례로 볼 수 있다. key share 우선 유형이 C2에게 고전을 준 동작은 RFC 8446이 허용하지만(클라이언트는 가장 선호하는 그룹의 key share를 생략할 수 있다, [1] 4.2.8절), key share 예측 초안의 "key_share를 이유로 PQ 그룹 대신 고전 그룹을 고르지 말라"는 권고와는 어긋난다 [21]. 이 초안은 규범이 아니므로 위반이라고 부르지는 않는다. OpenSSH는 선택 규칙이 규격에 고정되어 있고 상세 로그로 광고와 협상을 함께 확인할 수 있었으며, 누락은 관측되지 않았다. 따라서 답은 다음과 같다. **관측한 결함은 한 라이브러리의 우연한 버그이다. 그러나 PQ 보호가 구현 재량으로 정해지고 구현마다 다른 협상 함수에 달려 있으며 기본 출력으로 드러나지 않는다는 구조는, 시험한 다섯 TLS 구현 전반에 걸친 패턴이다.** 이 구조가 실제 C2형 PQ 누락으로 이어지려면 key share를 미루는 하이브리드 우선 클라이언트가 있어야 하며, 확장한 v1.8 기본값 표본과 두 브라우저에서는 찾지 못했다.

### 7.3 실무적 함의

첫째, 하이브리드 활성화 여부는 설정이나 연결 성공만으로 확인할 수 없다. 실제 협상 그룹을 기록하고 의도한 정책과 비교해야 한다. 상세 출력(`s_client -trace`, `tshark -V`)은 광고 그룹과 협상 그룹을 한 출력에 보여 주므로 이 비교의 재료가 되지만, 스스로 경고하지는 않는다. 둘째, 서버 패키지와 내장 TLS 런타임의 버전을 함께 확인해야 한다. 배포판의 Caddy 2.6.2는 직접 연결에서 다섯 클라이언트와 X25519를 협상했고 `tlsmlkem=0`을 포함했지만, 단일 원인은 아직 분리하지 않았다. 셋째, key share를 미루는 클라이언트를 받아야 하는 서버는 선택 유형을 확인해야 한다. OpenSSL에서는 하이브리드를 별도의 첫 tuple로 두거나 내장 기본 목록을 쓰면 HRR로 하이브리드를 요청했고, NSS의 기본 규칙으로는 하이브리드가 선택되지 않았다. PQ key share를 미루는 origin 연결을 받는 서버도 여기에 해당할 수 있다 [23]. 넷째, 영향받는 OpenSSL(CVE 레코드 기준 3.5.0–3.5.5, 3.6.0–3.6.1 [6])에서 서버 그룹 설정에 `DEFAULT`를 쓰면 key share를 미루는 클라이언트와의 연결이 고전으로 끝날 수 있다. 권고문은 3.5.6과 3.6.2로의 업그레이드를 권한다 [5].

## 8. 한계

실험은 로컬 loopback의 고정 테스트베드에서 수행했다. E8과 E9b의 클라이언트, E5–E7의 클라이언트는 모두 OpenSSL 3.5.5 하나이다. 서버는 각 구현의 기본 선택 모드와 하나의 서버 설정으로 시험했다(OpenSSL은 서버 선호 옵션도 시험). Go와 rustls는 최소 프로그램으로 시험했다. BoringSSL은 2024-08 빌드와 최신 commit `697ee71`의 C1–C3만 비교했으며, 최신 빌드의 기본 클라이언트 값은 조사하지 않았다. NSS 소스는 GitHub 미러의 3.120 릴리스 태그에서 읽었고, Ubuntu 패치 다섯 개가 `tls13con.c`·`sslsock.c`를 직접 수정하지 않음을 확인했지만 다른 경로의 효과까지 배제하지는 못했다. Caddy는 2.6.2와 공식 2.11.4를 대조했으나 두 바이너리에서 Caddy와 Go가 함께 바뀌므로 `tlsmlkem=0`의 인과를 분리하지 못했다. 2.6.2–rustls 직접 연결 3회는 ServerHello 없이 실패했으나 로그만으로 원인을 알 수 없었다. 기본 클라이언트와 기본 서버의 직접 연결은 36회 수행했지만, 기본 클라이언트를 Caddy 2.11.4에 직접 연결하지는 않았다. 반복은 E1–E7 10회, E8 5회, E9 계열·E10·`-trace` 재실행 3회이며 관측된 완료 연결의 결과는 결정적이었다.

기본값 조사는 loopback에서 라이브러리 기본값과 headless 브라우저 두 개(Chrome for Testing 154, Firefox 156)만 측정했다. v1.8의 8개 추가 라이브러리 표본에서 C2는 없었고 Botan C3 하나만 추가로 관측했다. 일반 배포판 브라우저의 원격 설정, 모바일 클라이언트, 인터넷 규모의 배포 빈도는 측정하지 않았다. 따라서 key share를 미루는 하이브리드 우선 클라이언트가 실제로 얼마나 있는지는 답하지 못한다. §3과 §7에서 인용한 공개 자료 [21, 22, 23]는 본 연구의 측정이 아니며, 측정 방법과 시점이 달라 본 결과와 직접 비교할 수 없다. Cloudflare의 origin 연결 방식은 2025년 10월 블로그의 설명이며, 현재 설정과 광고 순서는 확인하지 않았다.

경로상 조작 중 경로상 그룹 순서 조작은 수행하지 않았다. TLS의 PQ 성분 변조는 키 형식 검증에서 거부되어 컴바이너 결합 자체를 시험하지 못했고, SSH의 KEX 제거는 패킷 형식 오류로 끝나 협상 방어를 판정하지 못했다. 이 세 경우는 향후 과제로 남긴다. 교차 구현 협상 관측의 OpenSSH `ssh-order` 조건은 기본 조건과 같은 설정으로 실행되어 사실상 같은 조건의 반복이었다.

인과 분리는 두 계열 모두 수정 커밋의 `ssl/t1_lib.c` 변경만 넣고 뺐다. 감사 가시성은 기본 출력 세 경로를 정규식 수준으로, 상세 출력은 보존 캡처의 `tshark -V`와 OpenSSL 클라이언트의 `s_client -trace`(9회)로 측정했다. key log, 서버 쪽 상세 출력, 다른 구현의 상세 모드, E8–E10의 기본 출력은 측정하지 않았다. HRR 판정 파서는 여러 TCP 세그먼트에 걸친 메시지를 재조립하지 않는다. 교차 구현 결론은 시험한 구현과 그 버전·설정에 한정된다.

## 9. 결론

여섯 구현에서 하이브리드 키 교환의 PQ 보호를 두 영역으로 나누어 측정했다. 증명이 보장하는 경로상 조작에서는 결합 계층까지 도달한 조작이 모두 막혀, 구현이 증명의 예측대로 동작했다. 간극은 증명이 아니라, 증명이 기준으로 삼는 협상 함수에 있었다. 다섯 TLS 서버를 모두 하이브리드 우선으로 설정해도 협상 함수는 세 유형으로 갈렸고, key-share 우선 유형(OpenSSL 단일 tuple, NSS)은 하이브리드를 원하면서 key share를 미룬 C2에게 고전 그룹을 주었다. NSS 소스는 X25519와 `X25519MLKEM768`을 같은 256비트 강도로 두는 선택 규칙을 보이며, 이 선택을 설명한다. OpenSSL에서는 서버가 자기 정책을 어기는 결함(CVE-2026-2673)을 재현하고, 3.5와 3.6 두 계열에서 수정 변경 하나로 인과를 확정했다. v1.8의 실제 기본값 8개 확대 표본에서는 C2를 찾지 못했다. Botan은 C3으로서 서버 선택 유형에 따라 고전 또는 HRR 뒤 하이브리드를 받았지만, 이는 별도의 클라이언트 선호 고전 협상이다. 관측한 결함은 한 라이브러리의 것이지만, 실제 PQ 적용이 구현마다 다른 협상 함수와 클라이언트 key share 전략에 달린다는 구조는 시험한 다섯 TLS 구현 전반에서 관측됐다. PQ 전환에서 "하이브리드를 켰다"와 "하이브리드가 쓰이고 있다"는 별개로 확인해야 한다.

## 참고문헌

1. E. Rescorla, "The Transport Layer Security (TLS) Protocol Version 1.3", RFC 8446, August 2018. <https://www.rfc-editor.org/rfc/rfc8446>
2. D. Stebila, S. Fluhrer, S. Gueron, "Hybrid Key Exchange in TLS 1.3", RFC 9954, Informational, July 2026. <https://datatracker.ietf.org/doc/rfc9954/>
3. K. Kwiatkowski, P. Kampanakis, B. E. Westerbaan, D. Stebila, "Post-Quantum Traditional (PQ/T) Hybrid Key Agreement Mechanisms for TLS 1.3", RFC 10024, Proposed Standard, August 2026. <https://datatracker.ietf.org/doc/rfc10024/>
4. OpenSSL, `SSL_CTX_set1_curves(3)` manual page, OpenSSL 3.5. <https://docs.openssl.org/3.5/man3/SSL_CTX_set1_curves/>
5. OpenSSL Security Advisory [20260313], "OpenSSL TLS 1.3 server may choose unexpected key agreement group" (CVE-2026-2673). <https://openssl-library.org/news/secadv/20260313.txt>
6. CVE Record, CVE-2026-2673. <https://www.cve.org/CVERecord?id=CVE-2026-2673>
7. OpenSSL, commit `85977e013f32ceb96aa034c0e741adddc1a05e34`, "Fix group tuple handling in DEFAULT expansion" (3.5 branch). <https://github.com/openssl/openssl/commit/85977e013f32ceb96aa034c0e741adddc1a05e34>
8. OpenSSL, commit `2157c9d81f7b0bd7dfa25b960e928ec28e8dd63f`, "Fix group tuple handling in DEFAULT expansion" (3.6 branch). <https://github.com/openssl/openssl/commit/2157c9d81f7b0bd7dfa25b960e928ec28e8dd63f>
9. K. Bhargavan, C. Brzuska, C. Fournet, M. Green, M. Kohlweiss, S. Zanella-Béguelin, "Downgrade Resilience in Key-Exchange Protocols", IEEE Symposium on Security and Privacy, 2016.
10. B. Gupta, S. Rana, "Transcript-Bound Combiners for Downgrade-Resilient Hybrid Post-Quantum Key Establishment: Definition, Proof, and Embedded-Device Cost", arXiv:2609.21273, 2026.
11. B. Beurdouche et al., "A Messy State of the Union: Taming the Composite State Machines of TLS", IEEE Symposium on Security and Privacy, 2015.
12. D. Adrian et al., "Imperfect Forward Secrecy: How Diffie-Hellman Fails in Practice", ACM Conference on Computer and Communications Security (CCS), 2015.
13. T. Ylonen, C. Lonvick, "The Secure Shell (SSH) Transport Layer Protocol", RFC 4253, January 2006. <https://www.rfc-editor.org/rfc/rfc4253>
14. The Go Authors, `crypto/tls` package documentation, `Config.CurvePreferences`, Go 1.26. <https://pkg.go.dev/crypto/tls#Config>
15. rustls, `CryptoProvider::kx_groups` documentation, rustls 0.23.45. <https://docs.rs/rustls/0.23.45/rustls/crypto/struct.CryptoProvider.html>
16. BoringSSL, commit `7fb4d3da5082225c7180267e9daad291887ce982`, `ssl/extensions.cc` and `ssl/tls13_server.cc`. <https://boringssl.googlesource.com/boringssl/+/7fb4d3da5082225c7180267e9daad291887ce982/ssl/extensions.cc>
17. NSS, tag `NSS_3_120_RTM`, `lib/ssl/tls13con.c` and `lib/ssl/sslsock.c` (GitHub mirror). <https://github.com/nss-dev/nss/blob/NSS_3_120_RTM/lib/ssl/tls13con.c>
18. Caddy, v2.11.4 release and official binary checksums. <https://github.com/caddyserver/caddy/releases/tag/v2.11.4>
19. The Go Authors, "Go, Backwards Compatibility, and GODEBUG" (`tlsmlkem` history and defaults). <https://go.dev/doc/godebug>
20. D. Benjamin, "Applying Generate Random Extensions And Sustain Extensibility (GREASE) to TLS Extensibility", RFC 8701, January 2020. <https://www.rfc-editor.org/rfc/rfc8701>
21. D. Benjamin, "TLS Key Share Prediction", draft-ietf-tls-key-share-prediction-04, Internet-Draft (expired 20 September 2026), 19 March 2026. <https://www.ietf.org/archive/id/draft-ietf-tls-key-share-prediction-04.txt>
22. N. Wickramasinghe, F. Li, S. Jha, A. Shaghaghi, "Mind the Gap: Policy vs Reality in Post-Quantum TLS Deployment", arXiv:2607.29005, 31 July 2026. <https://arxiv.org/abs/2607.29005>
23. B. Westerbaan, "State of the post-quantum Internet in 2025", The Cloudflare Blog, 28 October 2025. <https://blog.cloudflare.com/pq-2025/>

## 부록 A. 재현 정보

원시 데이터(실행별 JSON 기록, 패킷 캡처, 클라이언트·서버·캡처·프록시 로그), 빌드 로그, 분석 코드는 저장소에 보존했다. 표본·환경·해시의 세부 근거는 `docs/EVIDENCE.md`, 재현 명령은 `docs/research/REPRODUCTION.md`에 있다.

- 데이터 위치(`docs/research/baselines/raw/`): E11 `v1.8/`(24회)와 Botan C3 정책 대조 `v1.8-e8/`(15회; `v1.8-diagnose/`는 제외), E8 `v1.5/`(105회), 최신 BoringSSL 대조 `v1.5-boringssl-latest/`(9회), E9 `v1.6/`(36회), 기본 직접 연결 `v1.6-direct/`(36회), v1.6 재실행 `v1.6-caddy-2.11.4/`(36회, Caddy 2.11.4 C1–C3 9회 포함), Caddy·NSS 원시 환경 확인 로그, E10과 `-trace` 재실행 `v1.7/`(15회)와 `v1.7-setup.log`, 상세 캡처 재측정 `v1.7-tshark-verbose-audit.json`, E5 `v1.2/`(60회)와 `v1.2-s4/`(보조 20회), E6 `v1.3/`(120회)와 `v1.3-build.log`, `v1.7-openssl36/`(60회)와 `v1.7-build36.log`·`v1.7-ldd36.log`, E7 `v1.4/`(60회), E1·E2 `phase-4/`(60회), E3·E4와 기본 협상 `v1.1/`(90회).
- 결과 재계산(`tools/`에서): `python -m faultinject.v18 --report ../docs/research/baselines/raw/v1.8`(E11 기본값), `python -m faultinject.v18 --report ../docs/research/baselines/raw/v1.8-e8`(Botan C3 정책 대조), `python -m faultinject.v15 --report ../docs/research/baselines/raw/v1.5`(E8), `python -m faultinject.v15 --report ../docs/research/baselines/raw/v1.5-boringssl-latest`(최신 BoringSSL), `python -m faultinject.v16 --report ../docs/research/baselines/raw/v1.6`(E9), `--report ../docs/research/baselines/raw/v1.6-direct`(직접 연결), `--report ../docs/research/baselines/raw/v1.6-caddy-2.11.4`(v1.6 재실행; Caddy 2.11.4 9회 포함), `python -m faultinject.analyze --v12`(E5, `CVE-2026-2673 verdict: reproduced`), `--v13`(E6, `Causal-isolation verdict: consistent`), `--v17`(E6 3.6 변형, `3.6 causal-isolation verdict: consistent`), `python -m faultinject.v17 --report ../docs/research/baselines/raw/v1.7 --verbose-json ../docs/research/baselines/raw/v1.7-tshark-verbose-audit.json`(E10, `-trace`, `tshark -V`), `--v12 --run-dir ../docs/research/baselines/raw/v1.4`(E7, 판정 줄 `reproduced`), `python -m faultinject.analyze`(E1·E2), `--v11`(E3·E4; 이 출력의 HRR 열은 수집 당시 기록이라 E3 OpenSSL을 0으로 보이며, 캡처 재검증 값 10/10은 `docs/EVIDENCE.md`에 있다). E8 서버는 `tools/v15_setup.sh`, E9의 클라이언트와 서버는 `tools/v16_setup.sh`, E10의 브라우저는 `tools/v17_setup.sh`로 준비한다(Go·rustls 소스는 `tools/v15/`).
- CVE 사례 바이너리: 클라이언트와 3.5.5 서버의 `openssl` SHA-256 `7b1a89948e5e…`, 3.5.6 `88a896e54ede…`, 3.6.1 `d1199e01f04d…`, 3.6.2 `5851a0b61487…`. 패치 변형 두 개는 실행 파일이 원본과 같고 `libssl.so.3`만 다르다(3.5.5-cherrypick `ef30c6d8de54…`, 3.5.6-revert `a9d8f36e38b2…`; 원본 3.5.5 `a785209382…`, 3.5.6 `aff23fc605…`). 3.6.1과 3.6.2의 `libssl.so.3`은 각각 `fb70fdbf1a67…`, `708d5e708526…`이고, 3.6 변형은 3.6.1-cherrypick `c06395759288…`, 3.6.2-revert `8aea8de16e26…`이다. 각 서버가 자신의 `libssl`을 로드함을 `ldd`로 확인했고, 실행 파일에는 RPATH/RUNPATH가 없다.
- 소스: 3.5.5 `67b5686b…`, 3.5.6 `286ddeaa…`, 3.6.1 `c9a9e5b1…`, 3.6.2 `fe686e15…`. 변형 빌드는 `tools/v13_build_variants.sh`로 만든다.
- HRR 판정 기준: 캡처된 ServerHello random이 RFC 8446 HRR 고정값 `cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c`인지.
- 재현 패키지: `dist/`의 v1.1–v1.7 ZIP은 각 실험의 원시 데이터와 문서, 도구, 테스트를 포함한다. S4 보조 표본은 저장소에만 있다. `dist/pq-hybrid-downgrade-repro.zip`은 초기(E1·E2) 패키지이다.

## 부록 B. 연구 경과와 정정

연구는 기획서의 구현 × 결함 유형 비교로 시작했다(E1, E2). 초기 분석은 E2의 거부를 모두 "바인딩 방어 성공"으로 해석했으나, 실패 원인을 다시 확인한 결과 TLS의 거부는 키 형식 검증에서 일어났음을 알게 되어 정정했다. 이후 경로상 제거(E3)와 공격자 없는 협상(E4)을 추가했다(v1.1). 처음에는 E4에서 OpenSSL의 HRR 부재를 결함 후보로 보았으나, 서버 설정이 단일 tuple이라 문서화된 동작임을 확인하고 해석을 정정했다. 또 OpenSSL 로그가 HRR을 `ServerHello`로 표기해 E3의 HRR이 수집 기록에서 누락된 것을 캡처로 바로잡았고, 이후 HRR 판정 기준을 캡처로 바꾸었다. 이 정정들이 E5(v1.2)와 E6(v1.3)으로 이어졌다. E7(v1.4)은 고전 우선 클라이언트라는 E5의 조건을 보완했고, E8(v1.5)은 RQ3의 근거를 다섯 TLS 구현으로 넓혔다. E9(v1.6)는 E8의 PQ 누락 조건이 기본 설정에서도 성립하는지 확인하려고 추가했으며, 그 결과 시험한 기본 클라이언트는 조건에 해당하지 않음을 확인하고 결론의 범위를 좁혔다. 이 판에서 공격자에 의한 "다운그레이드"와 공격자 없는 "PQ 누락"을 용어로 구분했다. v1.7에서는 남은 약점 세 가지를 보완했다. 3.6 계열의 인과 분리를 파일 단위로 반복했고, headless 브라우저 두 개의 ClientHello를 조사했으며, 감사 가시성을 상세 출력까지 넓혀 측정했다. v1.8에서는 실제 기본값 후보를 확장했다. 처음 Botan을 C2로 읽은 파생 분류를 원시 ClientHello 순서로 재검토해 C3으로 정정했고, 이후 다섯 서버 유형 대조를 추가했다. v1.9에서는 새 측정 없이 외부 공개 자료 세 건 [21, 22, 23]을 원문으로 확인해 관련 연구와 논의에 맥락으로 더했다. 확대 표본에는 C2가 없었고, Botan C3의 결과만 서버 선택 유형에 따라 갈렸다.

## 부록 C. 전체 실험 행렬

| 코드 | 실험 | 영역 | 방법 |
|---|---|---|---|
| E8 | 협상 함수 비교 | B | 다섯 TLS 서버 구현을 하이브리드 우선으로 설정하고 C1·C2·C3 고정 OpenSSL 클라이언트로 연결 |
| E9a | 클라이언트 기본값 조사 | B | 여섯 클라이언트 라이브러리를 그룹 설정 없이 OpenSSL 3.5.6 기본 서버에 연결하고 ClientHello 기록 |
| E9b | 실제 서버 소프트웨어 | B | 기본 nginx·Caddy에 C1–C3 연결 |
| E9c | 기본 클라이언트 × 기본 서버 직접 연결 | B | 여섯 기본 클라이언트를 기본 nginx·Caddy 2.6.2에 연결 |
| E10 | 브라우저 기본값 조사 | B | headless Chrome·Firefox로 ClientHello 기록 |
| E11 | 실제 기본값 확대와 Botan C3 정책 대조 | B | 추가 기본 클라이언트 8개를 조사하고 Botan C3을 다섯 서버 선택 유형에 연결 |
| E5 | 서버 설정 결함 사례 | B | OpenSSL S1 단일 tuple·S2 tuple 경계·S3 `DEFAULT`와 3.5.5·3.5.6 대조 |
| E6 | 인과 분리 | B | 3.5·3.6 수정 커밋의 `ssl/t1_lib.c` 변경만 넣고 빼서 E5 반복 |
| E7 | 하이브리드 우선 C2 | B | E5 서버·설정에서 C2 클라이언트로 반복 |
| E4 | 클라이언트 선호 고전 협상 | B | 하이브리드와 고전을 광고하되 고전을 1순위로 둔 클라이언트 연결 |
| E1 | 고전 전용 제시(기준선) | — | 클라이언트가 고전 그룹·KEX만 제시 |
| E2 | PQ 성분 변조 | A | 프록시가 하이브리드 공개값의 PQ 성분만 비트 반전 |
| E3 | 하이브리드 제거 | A | 프록시가 ClientHello 또는 SSH KEXINIT에서 하이브리드 항목 제거 |

## 부록 D. AI-대-인간 책임 공개

실험 도구(결함 주입 프록시, 대조 실행기, 패킷 캡처 파서, 감사 가시성 측정, 판정 코드), 변형 빌드 스크립트, 반복 실행 자동화, 원시 데이터 집계, 소스 코드 확인, 규범 분석 초안, 그리고 본 논문 초안의 작성에는 AI가 사용됐다. 각 단계의 산출물은 독립 AI 리뷰어가 원시 데이터와 대조해 검토했다. 저자는 연구 질문과 논문의 틀, 재현 판정 규칙, 실험 행렬과 인과 분리의 범위와 우선순위를 결정했다. 또한 해석 정정, 원시 데이터와 해시, 커밋 조상 관계, 결론의 범위를 검토하고 확인했다.
