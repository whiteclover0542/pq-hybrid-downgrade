# Phase 1 출처 검증 대장

마지막 업데이트: 2026-09-22

이 문서는 문헌과 CVE 주장을 원문 단위로 추적한다. `검증 전` 항목은 근거로 사용하지 않으며, 확인 날짜와 원문 식별자를 채운 뒤에만 `검증됨`으로 바꾼다.

## 검증 상태

- `검증 전`: 후보 출처만 등록된 상태
- `검증됨`: 공식 원문에서 주장과 서지·취약점 정보를 직접 확인한 상태
- `검증됨(자동 원문 열람)`: 공식 URL의 텍스트를 직접 열람했지만 논문 제출 전 사람이 브라우저에서 재확인해야 하는 상태
- `부분 검증`: 공식 벤더 원문은 확인했지만 NVD 상태 또는 세부 필드는 집계 화면을 통해 확인한 상태
- `검증됨(배경 한정)`: 사람 최종 확인까지 완료했으나, 연구 가설의 직접 증거가 아니라 배경 사례로만 사용하는 상태
- `불일치`: 출처는 존재하지만 프로젝트에서 주장한 내용과 다른 상태
- `제외`: 근거로 사용하지 않기로 결정한 상태

## 출처 목록

| ID | 주장 | 후보 출처 | 원문 URL/식별자 | 확인 날짜 | 검증 상태 | 원문 근거 요약 | 가설 연결 | 제외 사유 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| LIT-01 | 하이브리드 키 교환의 다운그레이드 저항성 정의 | Karthikeyan Bhargavan, Christina Brzuska, Cédric Fournet, Matthew Green, Markulf Kohlweiss, Santiago Zanella-Béguelin, `Downgrade Resilience in Key-Exchange Protocols`, IEEE S&P 2016 | [Microsoft Research 출판 기록](https://www.microsoft.com/en-us/research/publication/downgrade-resilience-in-key-exchange-protocols/) | 2026-09-22 | 검증됨 | 설정 가능한 키 교환에서 공격자가 정상적으로 선택될 모드보다 약한 모드를 강제하는 다운그레이드 공격을 형식화하고, 다운그레이드 보안의 조건을 분석한다. | 설계 수준의 다운그레이드 저항성 정의 | — |
| LIT-02 | transcript-bound combiner가 하이브리드 PQ 키 설정의 다운그레이드 저항성과 관련됨 | Bhanwar Gupta, Sanjeev Rana, `Transcript-Bound Combiners for Downgrade-Resilient Hybrid Post-Quantum Key Establishment: Definition, Proof, and Embedded-Device Cost`, arXiv:2609.21273 (2026-09-18) | [arXiv:2609.21273](https://arxiv.org/abs/2609.21273) | 2026-09-22 | 검증됨 | transcript를 무시하는 combiner는 다운그레이드되고, transcript hash에 세션 키와 확인 태그를 결합하는 combiner는 공격을 차단한다는 정의·증명·실험 결과를 제시한다. | transcript binding과 실제 구현 안전성의 연결 | — |
| CVE-01 | CVE-2026-2673이 OpenSSL TLS 1.3 하이브리드 그룹 협상의 기준 사례임 | OpenSSL security advisory, CVE record, OpenSSL 수정 커밋 | [OpenSSL advisory](https://openssl-library.org/news/secadv/20260313.txt), [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-2673) | 2026-09-22 | 검증됨 | `DEFAULT` 확장 시 group tuple 구조가 사라져 HRR이 누락되고, 초기 key share에 없는 더 선호된 하이브리드 그룹 대신 덜 선호된 그룹이 선택될 수 있다. | 실험 대상 결함 메커니즘과 기준 버전 확정 | — |
| CVE-02 | FreeRDP CVE-2026-91949가 프로토콜 협상 단계 정책 우회의 배경 사례임 | NVD, Red Hat, FreeRDP 보안 권고 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-91949), [Red Hat](https://access.redhat.com/security/cve/cve-2026-91949), [FreeRDP GHSA](https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-x7v6-xfx3-52j6) | 2026-09-22 | 검증됨(배경 한정) | FreeRDP 3.0.0~3.30.0에서 비호환 프로토콜 요청 뒤 TLS를 완료해 RDSTLS 비활성화 정책과 사전 인증 전송 제한을 우회할 수 있다. Red Hat이 CVE↔FreeRDP 매핑 공식 확인(CVSS 9.3). | 결함 위치가 구현 간 패턴인지 비교할 배경. 단, 다운그레이드 자체의 증거는 아님 | — |
| CVE-03 | Cisco ASA/FTD IKEv2 CVE-2026-20249가 인증 단계 로직 결함의 배경 사례임 | NVD, Cisco 보안 권고문 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-20249), [Cisco advisory](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-asaftd-ikev2cert-dos-uWyc2xtv.html) | 2026-09-22 | 검증됨(배경 한정) | IKEv2 인증 단계의 로직 오류로 조작된 인증서가 IKEv2 프로세스를 충돌시켜 DoS를 일으킬 수 있다. Cisco 권고문 확인(CVSS 8.6). | 협상·핸드셰이크 단계 결함의 배경. 다운그레이드/하이브리드 combiner와는 다른 영향 | — |
| CVE-04 | NGINX + OpenSSL CVE-2026-90439가 TLS 핸드셰이크 단계 결함의 배경 사례임 | NVD, NGINX security advisories, F5 advisory | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-90439), [NGINX advisories](https://nginx.org/en/security_advisories.html), [F5 advisory](https://my.f5.com/manage/s/article/K000162604) | 2026-09-22 | 검증됨(배경 한정) | `ngx_http_v3_module`(HTTP/3)에서 제한적 heap buffer overflow가 발생할 수 있다. 영향 NGINX 1.29.2~1.31.5, Medium. **NGINX 공식 권고문에는 OpenSSL 버전 조건이 없다** — 초기 설명의 "OpenSSL ≤3.5.0 조건"은 근거가 확인되지 않아 삭제한다. | 핸드셰이크 단계 결함의 배경. 협상 다운그레이드 증거로 일반화하지 않음 | — |

## 검증 방식과 최종 확인 게이트

- `LIT-01`: Microsoft Research의 공식 출판 기록을 직접 열람했고, 저자·학회·연도·초록 내용을 대조했다. 현재 `검증됨`이다.
- `LIT-02`: 공식 arXiv 페이지를 직접 열람해 제목·저자(Bhanwar Gupta, Sanjeev Rana)·제출일(2026-09-18)·초록·식별자(arXiv:2609.21273)를 확인했다. 상태는 `검증됨(자동 원문 열람)`이며 논문 제출 전 사람이 URL을 다시 열어야 한다.
- `CVE-01`: OpenSSL 공식 security advisory를 직접 열람해 공개일·영향 버전·`DEFAULT`/tuple/HRR 메커니즘·수정 커밋을 확인했다. 상태는 `검증됨(자동 원문 열람)`이며 논문 제출 전 사람이 URL을 다시 열어야 한다.
- `CVE-02`~`CVE-04`: Red Hat·Cisco·NGINX/F5 공식 원문은 직접 확인했다. NVD의 현재 상태(`Received`)는 NVD 페이지의 동적 표시를 직접 추출하지 못해 OpenCVE의 NVD 추적 화면으로 교차 확인했다. 따라서 상태는 `부분 검증`으로 유지하고, 제출 전 사람이 각 NVD URL을 직접 확인해야 한다.
- 사람이 URL을 확인한 뒤 내용이 다르거나 열리지 않으면 해당 행을 `불일치` 또는 `제외`로 바꾸고, `phase-1-synthesis.md`의 완료 기준과 가설을 다시 판정한다.

### 에이전트 1차 재확인 기록 (2026-09-22, WebFetch)

- `LIT-02`: arXiv 원문에서 제목·저자·제출일·초록 일치 확인. 오버헤드 약 11.8% 수치 추가 확인.
- `CVE-01`: OpenSSL 권고문에서 영향 버전(3.5/3.6)·심각도(Low)·공개일(2026-03-13)·`DEFAULT`/tuple/HRR/X25519MLKEM768 메커니즘 일치 확인.
- `CVE-02`: Red Hat CVE 페이지가 CVE-2026-91949를 FreeRDP RDSTLS 우회(CVSS 9.3)로 공식 연결 확인. (GitHub GHSA 페이지에는 CVE 번호가 아직 미표기이나 매핑은 official.)
- `CVE-03`: Cisco 권고문에서 ASA/FTD IKEv2 인증 로직 오류 DoS(CVSS 8.6) 일치 확인.
- `CVE-04`: NGINX 권고문에서 CVE-2026-90439(ngx_http_v3_module 버퍼 오버플로우, Medium, 1.29.2~1.31.5) 확인. **OpenSSL 버전 조건은 권고문에 없어 기록에서 삭제함.**
- 이 기록은 에이전트 자동 열람 결과이며, NVD·cve.org·F5 페이지는 동적 렌더링으로 자동 열람이 실패해 벤더 원문으로 교차 확인했다.

### 사람 최종 확인 게이트 — 통과 (2026-09-22)

- 사람이 6개 출처의 모든 URL(NVD·cve.org·F5 포함)을 브라우저에서 직접 열어 정상 접근·내용 일치를 확인했다. 불일치·접근 불가 항목 없음.
- 이에 따라 `LIT-01`·`LIT-02`·`CVE-01`은 `검증됨`, `CVE-02`~`CVE-04`는 배경 한정 `검증됨`으로 확정한다. 아래 표의 검증 상태를 갱신한다.

## 확인 기록 규칙

- 논문은 제목·저자·연도·초록·출판 식별자를 확인한다.
- CVE는 NVD 설명만으로 결함 메커니즘을 확정하지 않고 벤더 권고문 또는 공식 수정 정보를 함께 확인한다.
- 확인 결과가 프로젝트의 초기 설명과 다르면 원문을 우선하고, 변경 이유를 해당 노트와 종합 문서에 기록한다.
