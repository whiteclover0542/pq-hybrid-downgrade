# Phase 1 출처 검증 대장

마지막 업데이트: 2026-09-22

이 문서는 문헌과 CVE 주장을 원문 단위로 추적한다. `검증 전` 항목은 근거로 사용하지 않으며, 확인 날짜와 원문 식별자를 채운 뒤에만 `검증됨`으로 바꾼다.

## 검증 상태

- `검증 전`: 후보 출처만 등록된 상태
- `검증됨`: 공식 원문에서 주장과 서지·취약점 정보를 직접 확인한 상태
- `검증됨(자동 원문 열람)`: 공식 URL의 텍스트를 직접 열람했지만 논문 제출 전 사람이 브라우저에서 재확인해야 하는 상태
- `부분 검증`: 공식 벤더 원문은 확인했지만 NVD 상태 또는 세부 필드는 집계 화면을 통해 확인한 상태
- `불일치`: 출처는 존재하지만 프로젝트에서 주장한 내용과 다른 상태
- `제외`: 근거로 사용하지 않기로 결정한 상태

## 출처 목록

| ID | 주장 | 후보 출처 | 원문 URL/식별자 | 확인 날짜 | 검증 상태 | 원문 근거 요약 | 가설 연결 | 제외 사유 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| LIT-01 | 하이브리드 키 교환의 다운그레이드 저항성 정의 | Karthikeyan Bhargavan, Christina Brzuska, Cédric Fournet, Matthew Green, Markulf Kohlweiss, Santiago Zanella-Béguelin, `Downgrade Resilience in Key-Exchange Protocols`, IEEE S&P 2016 | [Microsoft Research 출판 기록](https://www.microsoft.com/en-us/research/publication/downgrade-resilience-in-key-exchange-protocols/) | 2026-09-22 | 검증됨 | 설정 가능한 키 교환에서 공격자가 정상적으로 선택될 모드보다 약한 모드를 강제하는 다운그레이드 공격을 형식화하고, 다운그레이드 보안의 조건을 분석한다. | 설계 수준의 다운그레이드 저항성 정의 | — |
| LIT-02 | transcript-bound combiner가 하이브리드 PQ 키 설정의 다운그레이드 저항성과 관련됨 | Bhanwar Gupta, Sanjeev Rana, `Transcript-Bound Combiners for Downgrade-Resilient Hybrid Post-Quantum Key Establishment: Definition, Proof, and Embedded-Device Cost`, arXiv:2609.21273 (2026-09-18) | [arXiv:2609.21273](https://arxiv.org/abs/2609.21273) | 2026-09-22 | 검증됨(자동 원문 열람) | transcript를 무시하는 combiner는 다운그레이드되고, transcript hash에 세션 키와 확인 태그를 결합하는 combiner는 공격을 차단한다는 정의·증명·실험 결과를 제시한다. | transcript binding과 실제 구현 안전성의 연결 | 사람 재확인 필요 |
| CVE-01 | CVE-2026-2673이 OpenSSL TLS 1.3 하이브리드 그룹 협상의 기준 사례임 | OpenSSL security advisory, CVE record, OpenSSL 수정 커밋 | [OpenSSL advisory](https://openssl-library.org/news/secadv/20260313.txt), [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-2673) | 2026-09-22 | 검증됨(자동 원문 열람) | `DEFAULT` 확장 시 group tuple 구조가 사라져 HRR이 누락되고, 초기 key share에 없는 더 선호된 하이브리드 그룹 대신 덜 선호된 그룹이 선택될 수 있다. | 실험 대상 결함 메커니즘과 기준 버전 확정 | 사람 재확인 필요 |
| CVE-02 | FreeRDP CVE-2026-91949가 프로토콜 협상 단계 정책 우회의 배경 사례임 | NVD, Red Hat, FreeRDP 보안 권고 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-91949), [Red Hat](https://access.redhat.com/security/cve/cve-2026-91949), [FreeRDP GHSA](https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-x7v6-xfx3-52j6) | 2026-09-22 | 부분 검증 | FreeRDP 3.0.0~3.30.0에서 비호환 프로토콜 요청 뒤 TLS를 완료해 RDSTLS 비활성화 정책과 사전 인증 전송 제한을 우회할 수 있다. NVD 상태는 `Received`이다. | 결함 위치가 구현 간 패턴인지 비교할 배경. 단, 다운그레이드 자체의 증거는 아님 | 사람 재확인 필요 |
| CVE-03 | Cisco ASA/FTD IKEv2 CVE-2026-20249가 인증 단계 로직 결함의 배경 사례임 | NVD, Cisco 보안 권고문 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-20249), [Cisco advisory](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-asaftd-ikev2cert-dos-uWyc2xtv.html) | 2026-09-22 | 부분 검증 | IKEv2 인증 단계의 로직 오류로 조작된 인증서가 IKEv2 프로세스를 충돌시켜 DoS를 일으킬 수 있다. NVD 상태는 `Received`이다. | 협상·핸드셰이크 단계 결함의 배경. 다운그레이드/하이브리드 combiner와는 다른 영향 | 사람 재확인 필요 |
| CVE-04 | NGINX + OpenSSL CVE-2026-90439가 TLS 핸드셰이크 단계 결함의 배경 사례임 | NVD, NGINX security advisories, F5 advisory | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-90439), [NGINX advisories](https://nginx.org/en/security_advisories.html), [F5 advisory](https://my.f5.com/manage/s/article/K000162604) | 2026-09-22 | 부분 검증 | `ngx_http_v3_module`에서 HTTP/3와 OpenSSL ≤3.5.0 조건 등에 따라 TLS 핸드셰이크 중 제한적 heap buffer overflow가 발생할 수 있다. NVD 상태는 `Received`이다. | 핸드셰이크 단계 결함의 배경. 협상 다운그레이드 증거로 일반화하지 않음 | 사람 재확인 필요 |

## 검증 방식과 최종 확인 게이트

- `LIT-01`: Microsoft Research의 공식 출판 기록을 직접 열람했고, 저자·학회·연도·초록 내용을 대조했다. 현재 `검증됨`이다.
- `LIT-02`: 공식 arXiv 페이지를 직접 열람해 제목·저자(Bhanwar Gupta, Sanjeev Rana)·제출일(2026-09-18)·초록·식별자(arXiv:2609.21273)를 확인했다. 상태는 `검증됨(자동 원문 열람)`이며 논문 제출 전 사람이 URL을 다시 열어야 한다.
- `CVE-01`: OpenSSL 공식 security advisory를 직접 열람해 공개일·영향 버전·`DEFAULT`/tuple/HRR 메커니즘·수정 커밋을 확인했다. 상태는 `검증됨(자동 원문 열람)`이며 논문 제출 전 사람이 URL을 다시 열어야 한다.
- `CVE-02`~`CVE-04`: Red Hat·Cisco·NGINX/F5 공식 원문은 직접 확인했다. NVD의 현재 상태(`Received`)는 NVD 페이지의 동적 표시를 직접 추출하지 못해 OpenCVE의 NVD 추적 화면으로 교차 확인했다. 따라서 상태는 `부분 검증`으로 유지하고, 제출 전 사람이 각 NVD URL을 직접 확인해야 한다.
- 사람이 URL을 확인한 뒤 내용이 다르거나 열리지 않으면 해당 행을 `불일치` 또는 `제외`로 바꾸고, `phase-1-synthesis.md`의 완료 기준과 가설을 다시 판정한다.

## 확인 기록 규칙

- 논문은 제목·저자·연도·초록·출판 식별자를 확인한다.
- CVE는 NVD 설명만으로 결함 메커니즘을 확정하지 않고 벤더 권고문 또는 공식 수정 정보를 함께 확인한다.
- 확인 결과가 프로젝트의 초기 설명과 다르면 원문을 우선하고, 변경 이유를 해당 노트와 종합 문서에 기록한다.
