# 배경 CVE 검증 노트

확인 날짜: 2026-09-22

이 세 CVE는 “협상·인증·핸드셰이크 경로의 결함이 겉보기 정상 흐름을 거쳐 보안 정책을 우회하거나 가용성을 훼손할 수 있다”는 배경을 비교하기 위한 것이다. 세 건 모두 하이브리드 PQ 다운그레이드의 직접 증거는 아니다.

## 비교표

| CVE | 확인 결과 | 영향 제품·버전 | 결함 위치/영향 | NVD 상태 | 프로젝트 관련성 |
| --- | --- | --- | --- | --- | --- |
| [CVE-2026-91949](https://nvd.nist.gov/vuln/detail/CVE-2026-91949) | FreeRDP 3.0.0~3.30.0 확인, 3.31.0 미영향 | FreeRDP server | 비호환 프로토콜 요청 뒤 TLS를 완료해 RDSTLS 비활성화 정책과 사전 인증 전송 제한 우회 | `Received` | 세 건 중 협상 단계 정책 우회와 가장 가까움. 하이브리드 PQ 다운그레이드 증거는 아님 |
| [CVE-2026-20249](https://nvd.nist.gov/vuln/detail/CVE-2026-20249) | Cisco 공식 권고문과 일치 | Cisco Secure Firewall ASA/FTD, IKEv2 인증 기능 | 인증 단계 로직 오류로 조작된 인증서가 IKEv2 프로세스 충돌·장치 reload·DoS 유발 | `Received` | 인증/핸드셰이크 경로 사례. 협상 다운그레이드와는 다른 영향 |
| [CVE-2026-90439](https://nvd.nist.gov/vuln/detail/CVE-2026-90439) | NGINX/F5 권고문과 일치 | NGINX Open Source 1.29.2~1.31.5 및 1.30.4 계열, NGINX Plus 관련 버전; HTTP/3와 OpenSSL ≤3.5.0 조건 | `ngx_http_v3_module`에서 TLS 핸드셰이크 중 제한적 heap buffer overflow, worker restart 또는 제한적 데이터 손상 가능 | `Received` | 핸드셰이크 경로 메모리 결함 사례. 협상 다운그레이드와는 다른 영향 |

## CVE-2026-91949 — FreeRDP

- Red Hat 설명은 비인증 공격자가 호환되지 않는 프로토콜 요청을 보내고 TLS handshake를 완료한 뒤, 서버가 비활성화한 RDSTLS 연결을 수립해 사전 인증 전송 제한을 우회할 수 있다고 기록한다.
- Red Hat 페이지의 CVSS 표에는 NVD 점수가 아직 `N/A`로 표시되어 있고, OpenCVE의 추적 정보에서도 NVD 상태가 `Received`이다.
- 출처: <https://access.redhat.com/security/cve/cve-2026-91949>, <https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-x7v6-xfx3-52j6>

## CVE-2026-20249 — Cisco ASA/FTD IKEv2

- Cisco 공식 권고문은 IKEv2 certificate authentication 단계의 logic error를 원인으로 설명한다.
- 공격자는 crafted certificate로 IKEv2 VPN 연결을 시도할 수 있고, 성공 시 IKEv2 프로세스가 crash되어 DoS가 발생한다.
- Cisco 권고문은 CVSS 8.6 High, CWE-704, IKEv2 및 certificate authentication 설정 조건을 기록한다.
- OpenCVE의 NVD 추적 상태는 `Received`이며, NVD 자체의 추가 분석이 완료된 것으로 보지 않는다.
- 출처: <https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-asaftd-ikev2cert-dos-uWyc2xtv.html>, <https://app.opencve.io/cve/CVE-2026-20249>

## CVE-2026-90439 — NGINX/OpenSSL HTTP/3

- NGINX security advisories는 이 CVE를 `ngx_http_v3_module` 사용 시 buffer overflow로 분류하고, NGINX Open Source의 취약 버전을 1.29.2~1.31.5로 제시한다.
- F5/CVE 설명은 HTTP/3와 OpenSSL 3.5.0 이하 조건에서 TLS handshake 처리 중 제한적 heap buffer overflow가 비결정적으로 발생할 수 있으며, worker restart 또는 제한적 데이터 손상을 일으킬 수 있다고 설명한다.
- NGINX 공식 목록은 1.31.6+ 및 1.30.5+를 미영향 버전으로 제시한다.
- OpenCVE의 NVD 추적 상태는 `Received`이다.
- 출처: <https://nginx.org/en/security_advisories.html>, <https://my.f5.com/manage/s/article/K000162604>, <https://app.opencve.io/cve/CVE-2026-90439>

## 종합 판단

FreeRDP는 프로토콜 협상 정책 우회라는 점에서 연구 주제와 가장 가까우나, Cisco와 NGINX는 각각 인증 단계 DoS와 HTTP/3 TLS 핸드셰이크 메모리 결함이다. 따라서 세 CVE를 “동일한 하이브리드 다운그레이드 패턴”으로 묶지 않고, 협상/핸드셰이크 경로 결함의 배경 사례라는 제한된 의미로만 사용한다.
