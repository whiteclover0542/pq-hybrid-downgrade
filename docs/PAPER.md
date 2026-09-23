# 협상 로직 결함에 의한 하이브리드-PQ 다운그레이드: 교차 구현 재현 연구

- 저자: whiteclover0542
- 날짜: 2026-09-23
- 한 줄 요약: 세 독립 TLS/SSH 구현(OpenSSL, BoringSSL, OpenSSH)에서 협상-목록 조작과 컴바이너 바인딩 위반을 통제 실험으로 재현해, 증명된-안전(proven-safe) 하이브리드-PQ 설계와 실제 배포 구현의 거동 사이 간극을 측정한다.

---

## 초록

TLS 1.3과 SSH의 하이브리드 PQ(post-quantum) 키 교환은 다운그레이드 저항성을 갖도록 설계되지만, 협상 로직의 결함은 이 설계를 고전 전용 그룹으로 되돌릴 수 있다(CVE-2026-2673). 본 연구는 이러한 다운그레이드가 특정 라이브러리의 우연한 버그인지, 독립 구현 전반의 패턴인지를 통제 실험으로 판정한다. 세 독립 구현(OpenSSL 3.5.5+oqs-provider, BoringSSL, OpenSSH portable)에 두 결함 유형—클라이언트 협상 목록(group-list) 조작과 컴바이너 바인딩(binding) 위반—을 조합당 10회씩 총 60회 WSL2 loopback에서 주입했다. group-list 조작은 세 구현 모두 10/10에서 하이브리드 그룹이 고전 그룹(X25519 또는 curve25519-sha256)으로 협상되었고 `downgrade_visible=true`였다(30/30). binding 위반은 세 구현 모두 10/10에서 핸드셰이크가 실패해 다운그레이드로 이어지지 않았다(`manipulation_verified=true`, downgrade 0/30). 가설("협상 결함발 다운그레이드는 버그가 아니라 패턴이다")은 벡터에 따라 부분적으로만 지지된다: group-list는 세 구현 전반의 패턴이나, binding은 세 구현 모두가 방어에 성공했다. 본 실험의 다운그레이드는 정상 로그에 그대로 기록되는 가시적 현상으로, CVE-2026-2673이 보고한 조용한(silent) 내부 폴백 특성은 재현하지 못했다. 결과는 로컬 loopback·3개 구현·고정 버전에 한정되며 실배포 네트워크나 다른 라이브러리로 일반화할 수 없다.

## 1. 서론

양자 컴퓨터의 발전에 대비해 TLS 1.3과 SSH는 고전 키 교환(X25519 등)과 PQ KEM(ML-KEM, Kyber, sntrup761)을 결합한 하이브리드 키 교환으로 이행하고 있다. 이 이행의 보안 목표 중 하나는 다운그레이드 저항성(downgrade resilience)이다. Bhargavan 등은 설정 가능한 키 교환 프로토콜에서 공격자가 협상을 조작해 더 약한 모드를 강제할 수 있는 다운그레이드 공격을 형식화하고, 이를 방어하기 위한 보안 조건을 정의했다[1]. 이 정의를 하이브리드 PQ 키 설정에 구체적으로 적용한 최근 연구로, Gupta와 Rana는 협상 transcript를 키 도출·확인 단계에 결합하는 transcript-bound combiner를 제시하고 그 다운그레이드 저항성을 형식적으로 증명했다[2].

그러나 이러한 설계가 수학적으로 증명된 안전성(proven-safe)을 갖는다는 것과, 실제 배포된 구현이 그 안전성을 유지한다는 것(as-deployed safe)은 별개의 문제다. 2026년 3월 공개된 CVE-2026-2673은 OpenSSL TLS 1.3 서버가 `DEFAULT` group tuple 처리 과정에서 group tuple 구조를 잃고 Hello Retry Request를 생략해, 클라이언트와 서버가 모두 `X25519MLKEM768` 같은 하이브리드 PQ 그룹을 지원함에도 초기 key share에 없으면 고전 전용 `X25519` 그룹이 선택될 수 있음을 보였다[3]. 이는 증명된-안전 설계 위에서도 구현 수준의 협상 로직 결함이 다운그레이드를 유발할 수 있다는 기준 사례다. 협상·인증·핸드셰이크 경로의 결함이 겉보기 정상 흐름을 거쳐 보안 정책을 우회하거나 가용성을 훼손하는 사례는 OpenSSL에 국한되지 않는다. FreeRDP의 프로토콜 협상 정책 우회[4], Cisco ASA/FTD의 IKEv2 인증 단계 로직 오류[5], NGINX HTTP/3 모듈의 TLS 핸드셰이크 중 heap buffer overflow[6]가 배경 사례로 확인되었다. 다만 이 세 건은 하이브리드 PQ 다운그레이드의 직접 증거가 아니며, 서로 다른 영향(정책 우회, 인증 단계 DoS, 메모리 결함)을 가지므로 동일한 패턴으로 묶지 않고 협상/핸드셰이크 경로 결함이라는 제한된 배경으로만 인용한다.

이로부터 본 연구의 가설과 연구 질문을 세운다. 가설은 "협상 로직 결함(supported_groups 조작 및 결합자 바인딩 위반)이 하이브리드-PQ 그룹을 고전 전용으로 다운그레이드시키는 것은 특정 라이브러리의 우연한 버그가 아니라 독립 코드베이스 전반의 패턴이다"이며, 연구 질문은 "협상 로직의 결함이 하이브리드 PQ 다운그레이드로 이어지는 것이 특정 라이브러리의 우연한 버그인지, 아니면 여러 구현체에 걸친 일반적 패턴인지"이다. 본 연구는 이 질문에 답하기 위해 세 독립 구현(OpenSSL, BoringSSL, OpenSSH)에 두 결함 유형을 통제된 loopback 환경에서 반복 주입하고, 그 거동을 원시 데이터로 측정한다.

## 2. 방법

**구현체.** 세 독립 TLS/SSH 구현을 고정 버전·커밋으로 빌드했다[phase-2-environment.md]. OpenSSL은 `openssl-3.5.5`(커밋 `67b5686b4419b4cb8caa502711c41815f5279751`)에 `oqs-provider 0.9.0`(커밋 `848b4e6abaa89e769c4db46ca78f91000f67ca52`)과 `liboqs 0.14.0`(커밋 `94b421ebb82405c843dba4e9aa521a56ee5a333d`)을 결합해 `X25519MLKEM768`을 협상 목표로 삼았다. OpenSSL 3.5.5는 프로젝트가 확인한 CVE-2026-2673 영향 범위(3.5.0~3.5.5, 수정판 3.5.6 이전)에 포함되는 수정 전 버전이다. BoringSSL은 커밋 `7fb4d3da5082225c7180267e9daad291887ce982`(2024-08-27)를 CMake/Ninja Release로 빌드했으며 목표 그룹은 `X25519Kyber768Draft00`(코드포인트 `0x6399`)이다. OpenSSH portable은 `V_10_2_P1`(커밋 `d01efaa1c9ed84fd9011201dbc3c7cb0a82bcee3`)을 custom OpenSSL 경로로 빌드했으며 목표 KEX는 `sntrup761x25519-sha512@openssh.com`이다. 모든 handshake는 WSL2 Ubuntu 26.04.1 loopback(`127.0.0.1`)에서 수행했고, 협상 상태 로그(`s_client -state`, `bssl client`, `ssh -vvv`), TLS keylog, `tshark` pcap을 감사 경로로 사용했다.

**결함 유형과 개입 지점.** 두 결함 유형을 정의했다[phase-3-experiment-design.md]. (1) `group-list`는 클라이언트 CLI의 그룹/KEX 목록을 조작해 하이브리드 그룹을 제외한 고전 전용 제안을 보내는 개입이다. (2) `binding`은 loopback MITM 프록시가 TLS `key_share` 또는 SSH `KEX_ECDH_INIT`의 PQ 성분 바이트만(길이를 바꾸지 않고 비트 반전) 위조하는 개입이며, 컴바이너의 transcript 바인딩이 위조된 PQ 성분을 탐지하는지를 시험한다. 관측 지표는 세 가지다: 협상 결과 그룹과 `is_hybrid`, 감사 경로에서 classical-only 협상이 드러나는지를 나타내는 `downgrade_visible`, 그리고 핸드셰이크 `success`/`failure`. 조작이 실제 통신에 반영되었는지는 `manipulation_verified`로 별도 검증하며, 검증에 실패한 실행은 취약성 판정 표본에서 제외한다.

**표본 설계와 도구.** 재현 도구는 `tools/faultinject/`(harness.py, fault_group_list.py, fault_binding.py, mitm_proxy.py, verify_applied.py, run.py, aggregate.py, analyze.py)이다. 3개 구현 × 2개 결함 유형 = 6개 조합에 대해 각 조합 최소 10회, 기본 배치 `--repeat 10`으로 총 60회(6조합 × 10회)를 실행했다[phase-4-execution.md]. 2026-09-23 06:13:17~06:16:50 KST 사이 1회 배치로 전 조합이 `verified=10(≥10)`을 충족해 보충 배치가 불필요했다. 각 실행의 client/server log, pcapng, JSON 레코드, binding 실패 시 proxy.log를 `docs/research/baselines/raw/phase-4/`에 보존했고, `python -m faultinject.aggregate`로 `manifest.csv`를 생성했다.

## 3. 결과

`tools/faultinject/manifest.csv`(`python -m faultinject.analyze`로 재생성 가능)의 집계는 다음과 같다.

| implementation | fault_type | total | verified | success | downgrade |
| --- | --- | --- | --- | --- | --- |
| boringssl | binding | 10 | 10 | 0 | 0 |
| boringssl | group-list | 10 | 10 | 10 | 10 |
| openssh | binding | 10 | 10 | 0 | 0 |
| openssh | group-list | 10 | 10 | 10 | 10 |
| openssl | binding | 10 | 10 | 0 | 0 |
| openssl | group-list | 10 | 10 | 10 | 10 |

**group-list 벡터**: 세 구현(OpenSSL, BoringSSL, OpenSSH) 모두 조합당 10/10에서 하이브리드 그룹이 고전 전용 그룹으로 협상되었다. OpenSSL과 BoringSSL은 `negotiated_group=X25519`, OpenSSH는 `negotiated_group=curve25519-sha256`이었으며, 세 구현 모두 `handshake_result=success`, `downgrade_visible=true`, `manipulation_verified=true`였다(원자료: `docs/research/baselines/raw/phase-4/{boringssl,openssh,openssl}_group-list_r0{1..10}_default.json`). `downgrade_visible=true`는 30/30 실행 전체에서 성립했다.

**binding 벡터**: 세 구현 모두 조합당 10/10에서 `handshake_result=failure`, `manipulation_verified=true`였다. OpenSSL·BoringSSL은 `negotiated_group=null`(그룹이 기록되기 전에 실패), OpenSSH는 `negotiated_group=sntrup761x25519-sha512@openssh.com`(하이브리드 KEX 이름이 기록된 뒤 실패, `is_hybrid=true`)이었다. 세 구현 모두 `downgrade_visible=false`였고, `success=0`으로 전원 방어(다운그레이드 0/30)였다.

## 4. 논의

**가설 판정.** 가설은 벡터에 따라 부분적으로 지지된다. group-list 조작에서는 세 구현 전반의 패턴이 관측됐고(30/30 다운그레이드), binding 위반에서는 세 구현 모두가 방어에 성공했다(0/30 다운그레이드). 데이터가 뒷받침하는 것은 "이 두 결함 유형 각각에서 세 구현이 동일하게 반응한다"는 것이지, "모든 협상 결함이 다운그레이드로 이어지는 패턴"이라는 확대된 주장이 아니다. binding 벡터가 정반대(전원 방어) 결과를 보였으므로, 결함 유형에 따라 결과가 갈린다는 점 자체가 이 연구의 핵심 발견이다.

**Divergence A — binding 벡터의 전면 거부.** 가설은 다운그레이드 패턴이 확장 적용될 가능성을 기대했으나, 관측은 세 구현 모두 전원 거부였다. 후보 원인은, 세 구현 모두 하이브리드 키 교환의 transcript/exchange-hash(또는 이에 상응하는) 바인딩이 PQ 성분 변조를 무결성 검증 단계에서 탐지해 핸드셰이크를 실패시킨다는 것이다. 즉 Gupta & Rana의 증명된-안전 transcript-bound combiner 설계[2](Bhargavan et al. 2016의 다운그레이드 저항성 정의[1]를 만족하도록 증명됨)가, 이 벡터에 한해서는 as-deployed 구현에서도 유지되는 것으로 보인다.

**Divergence B — 가시적 다운그레이드 대 CVE의 조용한 다운그레이드.** group-list 다운그레이드는 CVE-2026-2673의 "조용한(silent)" 특성과 달리 가시적이었다(`downgrade_visible=true`, 30/30). 후보 원인은, 본 실험의 group-list 결함이 클라이언트가 CLI에서 고전 전용 그룹 목록을 스스로 제시하는 조작이어서 그 결과인 고전 협상이 정상 프로토콜 로그에 그대로 기록되는 반면, CVE-2026-2673은 OpenSSL의 `DEFAULT`/tuple 처리 또는 HRR 내부 경로에서 발생하는 감사 우회형 조용한 폴백이라는 차이다. 따라서 본 실험이 시험한 것은 "협상 로직이 고전-전용 제시를 수용하는가"이며, "그 수용이 감사 로그에서 은폐되는가"는 시험하지 못했다. **CVE-2026-2673이 보고한 조용한(silent) 특성은 본 실험에서 재현되지 않았다는 점을 명시한다.**

**결론.** `supported_groups` 조작에 의한 하이브리드→고전 다운그레이드는 세 독립 구현(OpenSSL, BoringSSL, OpenSSH) 모두에서 재현됐다(각 10/10, `downgrade_visible=true`, 총 30/30). 결합자 바인딩 위반은 세 구현 모두에서 거부됐다(각 10/10 `handshake_result=failure`, 다운그레이드 0/30). 따라서 "협상-목록 수준의 다운그레이드 수용"은 세 구현에 걸친 패턴으로 관측되었으나, "바인딩 위반을 통한 다운그레이드"는 본 실험의 관측 범위에서 전혀 나타나지 않았다. 가설은 두 결함 유형을 하나로 묶어 지지되지 않으며, 결함 유형별로 상반된 결과가 나왔다는 것이 이 연구의 핵심 발견이다.

**한계.** (1) group-list는 진짜 경로상(on-path) MITM 스트리핑이 아니다. 본 실험의 group-list 조작은 클라이언트가 CLI 옵션으로 자신의 `supported_groups`를 고전 전용으로 스스로 제한하는 것이며, 공격자가 네트워크 경로에서 하이브리드 제안을 가로채 제거하는 시나리오를 재현한 것이 아니다. (2) 다운그레이드의 가시성이 CVE-2026-2673과 다르다. 본 실험의 다운그레이드는 정상 프로토콜 로그에 그대로 기록되는 가시적 현상이며, CVE-2026-2673이 보고한 조용한 내부 폴백 특성은 재현되지 않았다. (3) binding 프록시는 무결성 실패를 강제로 유도한다. 따라서 "조용한 수용"(위조된 PQ 성분이 탐지되지 않고 핸드셰이크가 성공으로 이어지는 경우)이 존재하는지는 본 실험 설계로는 관측할 수 없다 — 관측된 것은 "거부됨"뿐이며 "왜 항상 거부되는지"의 경계 조건은 확인되지 않았다. (4) 로컬 loopback, 3개 구현, 고정 버전에 한정된다. 실배포 네트워크 환경(지연, 중간 장비, 실제 MITM 조건)이나 본 연구가 다루지 않은 다른 TLS/SSH 구현·라이브러리 버전으로 일반화할 수 없다.

## 참고문헌

[1] Karthikeyan Bhargavan, Christina Brzuska, Cédric Fournet, Matthew Green, Markulf Kohlweiss, Santiago Zanella-Béguelin, "Downgrade Resilience in Key-Exchange Protocols," IEEE Symposium on Security and Privacy (S&P), 2016. https://www.microsoft.com/en-us/research/publication/downgrade-resilience-in-key-exchange-protocols/

[2] Bhanwar Gupta, Sanjeev Rana, "Transcript-Bound Combiners for Downgrade-Resilient Hybrid Post-Quantum Key Establishment: Definition, Proof, and Embedded-Device Cost," arXiv:2609.21273, 2026-09-18. https://arxiv.org/abs/2609.21273

[3] CVE-2026-2673 — OpenSSL Security Advisory, 2026-03-13; CVE Record. https://openssl-library.org/news/secadv/20260313.txt , https://www.cve.org/CVERecord?id=CVE-2026-2673

[4] CVE-2026-91949 — FreeRDP protocol-negotiation policy bypass (background). NVD. https://nvd.nist.gov/vuln/detail/CVE-2026-91949

[5] CVE-2026-20249 — Cisco ASA/FTD IKEv2 authentication-stage logic error (background). NVD. https://nvd.nist.gov/vuln/detail/CVE-2026-20249

[6] CVE-2026-90439 — NGINX HTTP/3 (`ngx_http_v3_module`) heap buffer overflow (background). NVD. https://nvd.nist.gov/vuln/detail/CVE-2026-90439

## 부록: AI-대-본인 판단 공개

(1) AI가 수행: 결함 주입 도구(`tools/faultinject/`) 구현, 60회 실험 실행, 본 문서를 포함한 문서·논문 초안 작성, 구현체별 비교표·분석 조립.

(2) 사람이 수행·결정: 연구 주제·가설 설정, 대상 3개 구현/버전(OpenSSL+oqs-provider, BoringSSL, OpenSSH) 선정, 각 참고문헌의 직접 열람·최종 검증 게이트, 가설 판정·결론 승인.

(3) 검증 방식: 인용마다 원문 직접 열람 확인, 원시 데이터 SHA-256 해시/재실행 검증, 논문 수치의 `manifest.csv` 대조.

> ⚠️ 위 3줄은 초안입니다 — 저자(사람)의 실제 기여에 맞게 검토·수정·승인이 필요합니다.
