# Phase 1 종합 노트

마지막 업데이트: 2026-09-22

## 검증된 출처 요약

- `LIT-01`: Bhargavan et al., *Downgrade Resilience in Key-Exchange Protocols*, IEEE S&P 2016. 설정 가능한 키 교환에서 약한 모드가 강제되는 다운그레이드 공격을 형식화한다.
- `LIT-02`: Gupta and Rana, *Transcript-Bound Combiners for Downgrade-Resilient Hybrid Post-Quantum Key Establishment: Definition, Proof, and Embedded-Device Cost*, arXiv:2609.21273, 2026-09-18. 공식 arXiv 원문은 자동 열람으로 확인했으며, 사람의 최종 재확인이 남아 있다.
- `CVE-01`: CVE-2026-2673은 OpenSSL 3.5/3.6의 `DEFAULT` group tuple 처리와 HRR 누락 문제로 확인되었다. 영향 범위는 3.5.0~3.5.5 및 3.6.0~3.6.1이다. OpenSSL 공식 권고문은 자동 열람으로 확인했으며, 사람의 최종 재확인이 남아 있다.
- `CVE-02`~`CVE-04`: 공식 벤더 원문은 확인했지만 NVD 상태는 집계 화면을 통한 `Received` 확인이므로 `부분 검증`으로 유지한다. 세 건을 동일한 하이브리드 다운그레이드 취약점으로 일반화할 근거는 없다.

## 알려진 사실과 이번 연구의 새 주장

| 구분 | 내용 | 필요한 증거 | 판정 상태 |
| --- | --- | --- | --- |
| 이미 알려진 사실 | 설정 가능한 키 교환에서 약한 모드가 강제되는 다운그레이드 공격과 그 보안 조건이 형식화되어 있다. | LIT-01 원문 | 충족 |
| 이미 알려진 사실 | transcript-bound combiner가 하이브리드 PQ 키 설정에서 협상 transcript를 키 도출·확인에 결합하는 설계로 제시되어 있다. | LIT-02 원문 | 원문 확인(자동), 사람 재확인 필요 |
| 기준 사례 | CVE-2026-2673은 `DEFAULT` group tuple 처리 오류와 HRR 누락으로 덜 선호된 key agreement group을 선택할 수 있다. | CVE-01 OpenSSL 권고문·수정 커밋 | 원문 확인(자동), 사람 재확인 필요 |
| 배경 사실 | FreeRDP·Cisco·NGINX에 협상·인증·TLS 핸드셰이크 경로의 별도 결함 사례가 존재한다. | CVE-02~CVE-04 원문 및 NVD 상태 | 공식 원문 확인, NVD 상태 간접 확인 |
| 이번 연구의 새 주장 | 협상 로직 결함발 하이브리드-PQ 다운그레이드가 단일 라이브러리 버그인지 독립 구현 전반의 패턴인지 실험으로 판정할 수 있다. | Phase 2~5의 baseline, 조작 실험, 원자료 | 검증 전 |

## Phase 1 완료 기준

- [x] 검증된 선행연구가 최소 1건 이상 목록에 있다.
- [x] 각 인용의 존재 검증 방법과 원문 식별자가 기록되어 있다.
- [x] 알려진 사실과 이번 연구의 새 주장이 분리되어 있다.
- [x] CVE-2026-2673의 권고문·영향 버전·결함 메커니즘이 분석 노트에 정리되어 있다.
- [x] FreeRDP·Cisco·NGINX 배경 CVE가 NVD에서 재확인되어 있다.
- [x] 존재하지 않거나 불일치하는 인용은 사유와 함께 제외되어 있다.

## 사람 최종 확인 게이트

아래 항목은 에이전트의 자동 원문 열람으로는 닫지 않는다. 논문 본문에 인용하기 전 사람이 브라우저에서 URL을 직접 열고 대장과 대조한다.

- [ ] LIT-02 arXiv 페이지에서 제목·저자·제출일·초록 확인
- [ ] CVE-2026-2673 OpenSSL 권고문에서 영향 버전·`DEFAULT`/tuple/HRR 메커니즘 확인
- [ ] CVE-02~CVE-04의 NVD 페이지가 열리고 CVE 번호·제품·설명이 일치하는지 확인
- [ ] 불일치 또는 접근 불가 항목을 `불일치`/`제외`로 변경하고 가설·종합 노트 재판정

## Phase 2 인계 조건

Phase 1 완료 기준을 모두 충족한 뒤에만 다음 항목을 고정하고 실험 환경 구축으로 넘어간다.

- OpenSSL + oqs-provider 대상 버전·커밋: OpenSSL 3.5.0~3.5.5 또는 3.6.0~3.6.1 중 재현할 정확한 커밋을 선택
- BoringSSL 대상 버전·커밋
- OpenSSH 대상 버전·커밋
- 각 구현체의 정상 하이브리드 핸드셰이크에서 관찰할 baseline 값
