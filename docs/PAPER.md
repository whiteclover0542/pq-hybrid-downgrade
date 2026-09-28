# 하이브리드 광고와 `key_share` 순서에 따른 PQ 키 교환 결과: HRR 부재와 감사 가시성의 교차 구현 관측

- 저자: whiteclover0542
- 문서 갱신: 2026-09-28
- 데이터 기준: v1.1 P2 최종 데이터셋(2026-09-25)

## 초록

[확실] 본 연구는 하이브리드 PQ 키 교환을 광고하는 TLS 1.3 클라이언트가 고전 `key_share`를 먼저 제시할 때의 협상 결과와 감사 가시성을 관측합니다. OpenSSL, BoringSSL, OpenSSH의 9개 구현×조건 조합을 각각 10회씩 실행하여, 최종 JSON 90건과 PCAP·클라이언트 로그·캡처 로그를 보존했습니다. OpenSSL과 BoringSSL의 `silent-downgrade` 조건은 각각 10/10 성공했고, 기록된 협상 그룹은 모두 고전 `X25519`, HRR은 0회, 자동 다운그레이드 표시는 0회였습니다. 반대로 검증된 `onpath-strip` 조건은 두 TLS 구현에서 각각 10/10 핸드셰이크 실패를 기록했습니다. OpenSSH의 경로상 조건도 10/10 실패했으며, 이는 TLS `key_share`/HRR과 직접 동등하지 않은 구조적 대조군입니다.

[불확실] 이 결과는 시험한 그룹 순서·버전·loopback 환경·감사 정의에 한정됩니다. RFC 적합성, 실배포 공격 가능성, CVE 재현 또는 새로운 취약점 여부는 이 데이터만으로 판정할 수 없습니다.

## 1. 서론

[확실] 하이브리드 PQ 키 교환에서 클라이언트의 지원 그룹 광고와 실제 `key_share` 제시, 서버의 선택, Hello Retry Request(HRR), 그리고 감사 출력은 서로 다른 관측 지점입니다. v1.1은 이 지점들이 일치하지 않을 때 실제 협상이 어떻게 기록되는지를 반복 실험으로 측정합니다.

[확실] v1.0은 클라이언트가 CLI로 고전 그룹만 제시한 group-list 실험과 PQ 성분 변조 대조 실험을 수행했습니다. 그 결과는 구성상 고전만 제시하면 고전 협상이 가능하고 변조는 실패한다는 가시적 관측이었지만, 하이브리드 광고 상태에서 `key_share` 순서가 협상과 감사에 미치는 영향을 시험하지 못했습니다. 따라서 v1.1에서는 v1.0을 동등한 결과 축으로 반복하지 않고, 그 한계를 보완하는 후속 설계를 주 결과로 삼습니다.

[확실] 연구 질문은 다음과 같습니다. 하이브리드를 광고하고 서버가 하이브리드를 선호하는 TLS 구성에서, 클라이언트가 고전 `key_share`를 먼저 보낼 경우 HRR 없이 고전 협상이 완료되는가? 또한 선택한 감사 경로가 광고된 하이브리드와 실제 고전 협상의 불일치를 자동으로 표면화하는가?

## 2. 방법

### 2.1 데이터 경계와 구현

[확실] 모든 수치의 유일한 출처는 `docs/research/baselines/raw/v1.1/`의 최종 JSON 90건입니다. 이전 63건 보존본, preflight 출력, 그리고 모든 `v1.1-diagnose*` 디렉터리는 결과 집계와 해석에서 제외했습니다. 최종 실행은 상태 코드 0과 빈 stderr 로그로 종료됐으며, 90개의 PCAP·클라이언트 로그·캡처 로그와 30개의 경로상 프록시 로그가 존재합니다.[1]

[확실] 구현은 고정된 v1.1 환경의 OpenSSL(+oqs-provider), BoringSSL, OpenSSH portable입니다. TLS의 하이브리드 협상 그룹은 각각 `X25519MLKEM768`, `X25519Kyber768Draft00`이며, OpenSSH의 하이브리드 KEX는 `sntrup761x25519-sha512@openssh.com`입니다.[2]

### 2.2 조건과 지표

[확실] 유효 조합은 9개입니다. OpenSSL과 BoringSSL은 `base`, `silent-downgrade`, `onpath-strip`을 실행했고, OpenSSH는 `base`, `ssh-order`, `onpath-strip`을 실행했습니다. 각 조합은 r01부터 r10까지 정확히 한 번씩 존재합니다.

[확실] `silent-downgrade`는 TLS에서 하이브리드를 광고하면서 고전 `key_share`를 먼저 제시하고, 서버는 하이브리드를 선호하도록 구성한 조건입니다. `onpath-strip`은 정상 하이브리드 제안에서 프록시가 하이브리드 그룹 또는 KEX를 제거하는 조건입니다. OpenSSH의 `ssh-order`는 SSH의 첫 매치 KEX 목록 순서를 관측하는 대조 조건이며 TLS의 `key_share`/HRR 조건과 동등하지 않습니다.[2]

[확실] 각 실행은 협상 그룹/KEX, 성공·실패, `manipulation_verified`, `advertised_hybrid`, `hrr_present`, `downgrade_flagged`, `is_hybrid`를 기록합니다. 여기서 “silent”는 선택한 client log, 상태 로그, keylog, PCAP 관측 경로가 광고-협상 불일치를 자동으로 표면화했는지를 뜻하는 조작적 정의입니다.

## 3. 결과

[확실] 아래 표는 P3에서 최종 JSON을 직접 집계한 결과입니다. 모든 행은 `advertised_hybrid=10`이며, `verified`는 `manipulation_verified=true`의 수입니다.

| 구현 | 조건 | 전체 | 성공 | 실패 | verified | HRR 있음 | 자동 flag | 하이브리드 협상 | 기록된 그룹/KEX |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|
| OpenSSL | base | 10 | 10 | 0 | 10 | 0 | 0 | 10 | X25519MLKEM768 |
| OpenSSL | silent-downgrade | 10 | 10 | 0 | 10 | 0 | 0 | 0 | X25519 |
| OpenSSL | onpath-strip | 10 | 0 | 10 | 10 | 0 | 0 | 0 | X25519 |
| BoringSSL | base | 10 | 10 | 0 | 10 | 0 | 0 | 10 | X25519Kyber768Draft00 |
| BoringSSL | silent-downgrade | 10 | 10 | 0 | 10 | 0 | 0 | 0 | X25519 |
| BoringSSL | onpath-strip | 10 | 0 | 10 | 10 | 0 | 0 | 0 | — |
| OpenSSH | base | 10 | 10 | 0 | 10 | 0 | 0 | 10 | sntrup761x25519-sha512@openssh.com |
| OpenSSH | ssh-order | 10 | 10 | 0 | 10 | 0 | 0 | 10 | sntrup761x25519-sha512@openssh.com |
| OpenSSH | onpath-strip | 10 | 0 | 10 | 10 | 0 | 0 | 10 | sntrup761x25519-sha512@openssh.com |

[확실] 두 TLS 구현의 `silent-downgrade` 20건은 모두 성공, 고전 `X25519` 협상, HRR 부재, 자동 flag 부재를 기록했습니다. 같은 구현들의 `base` 20건은 모두 하이브리드 협상에 성공했습니다. 따라서 이 데이터는 시험한 구성에서 `key_share` 순서가 결과 그룹을 바꾼다는 관측을 제공합니다.[3]

[확실] TLS `onpath-strip`은 OpenSSL과 BoringSSL에서 각각 10/10 실패했고 조작은 모두 검증됐습니다. 이는 시험한 alteration이 transcript 보호와 양립하는 실패 결과를 냈다는 관측입니다. OpenSSH `onpath-strip` 역시 10/10 실패했지만, harness가 파싱한 하이브리드 KEX와 `is_hybrid=true`를 기록했으므로 성공한 다운그레이드로 해석하지 않습니다.[3]

## 4. 논의와 한계

[확실] 조건 C의 관측은 두 독립 TLS 구현에서 공통입니다. 하이브리드 지원을 광고했지만 고전 `key_share`를 먼저 보낸 시험 구성에서, 서버는 기록된 HRR 없이 고전 핸드셰이크를 완료했습니다. 같은 20건에서 `downgrade_flagged=false`였으므로, 선택한 표준 감사 경로는 광고-협상 불일치를 자동으로 경고하지 않았습니다.

[확실] 조건 A의 결과는 별개입니다. 정상 제안에서 하이브리드 성분을 경로상 제거한 검증된 실험은 TLS에서 모두 실패했습니다. 따라서 “`key_share` 순서에 의한 성공한 고전 협상”과 “패킷 변조가 성공한다”는 서로 다른 주장입니다. 후자는 이 실험에서 관측되지 않았습니다.

[확실] OpenSSH는 TLS 결론의 세 번째 표본이 아닙니다. SSH에는 TLS의 `key_share`와 HRR 구조가 없으므로, OpenSSH 결과는 구조적 대조군으로만 해석합니다. `ssh-order`는 하이브리드 KEX를 유지한 채 성공했고, `onpath-strip`은 연결 실패로 끝났습니다.

[불확실] 서버가 이미 받은 사용 가능한 고전 `key_share`를 사용한 거동이 TLS 규격에 위배되는지 여부는 이 실험이 판정하지 않습니다. 이 데이터에는 규격의 규범적 해석, 소스 수준의 CVE 경로 분석, 인증된 완전 MITM, 또는 실배포 환경에서의 공격 효과가 없습니다.

[확실] 추가 한계는 고정 구현·버전, loopback 환경, 10회 반복, 그리고 감사 가시성의 조작적 정의입니다. PCAP과 로그에는 사람이 비교할 수 있는 근거가 남아 있지만, 자동 `downgrade_flagged`가 없다는 사실은 수동 분석도 불가능하다는 뜻이 아닙니다.

## 5. 결론

[확실] 시험한 그룹 순서와 감사 정의에서, OpenSSL과 BoringSSL은 하이브리드 광고 뒤에도 기록된 HRR 및 자동 다운그레이드 flag 없이 고전 핸드셰이크를 완료했습니다. 반면 검증된 경로상 하이브리드 제거는 TLS에서 실패했습니다.

[불확실] 이 결론은 관측 범위를 넘어 RFC 비준수, 실배포 취약점, CVE 재현 또는 공격 가능성을 주장하지 않습니다. 그러한 판단에는 별도의 규범적 분석과 더 넓은 환경의 증거가 필요합니다.

## 참고 자료

[1] v1.1 P2 Repeated Execution Summary, `.planning/phases/07-v11-tooling/07-02-SUMMARY.md`.

[2] v1.1 HRR-absence hybrid-downgrade design, `docs/research/2026-09-23-v1.1-hrr-downgrade-design.md`.

[3] v1.1 P3 Analysis, `docs/research/v1.1-p3-analysis.md`.

## 부록: AI-대-인간 책임 공개

[확실] AI는 fault-injection 도구 확장, 반복 실험 자동화, 원시 데이터 집계, 문서 초안 작성에 사용됐습니다.

[확실] 인간은 연구 질문과 범위를 결정하고, 구현·버전·출처·실험 환경을 검토했으며, 원시 데이터와 최종 결론의 범위를 확인했습니다.

[확실] 최종 검증은 원시 JSON·PCAP·로그의 존재와 집계값, 테스트 결과, 재현 ZIP 검증을 함께 대조하는 방식으로 수행합니다.
