# 하이브리드-PQ 다운그레이드 저항성 분석 (Phase 5)

## 가설

협상 로직 결함(supported_groups 조작 및 결합자 바인딩 위반)이 하이브리드-PQ 그룹을 고전 전용으로 다운그레이드시키는 것은 특정 라이브러리의 우연한 버그가 아니라 독립 코드베이스 전반의 패턴이다.

## 연구 질문

협상 로직의 결함이 하이브리드 PQ 다운그레이드로 이어지는 것이 특정 라이브러리의 우연한 버그인지, 아니면 여러 구현체에 걸친 일반적 패턴인지.

## 증명된-안전 대 배포된-안전

하이브리드 컴바이너 다운그레이드 저항성은 Bhargavan et al.의 공식 증명(Transcript-Bound Combiners, 2026-09)에 의해 정의된 설계(proven-safe)이다. 본 연구는 그 설계의 실제 배포 구현들(as-deployed safe) 거동을 현지 루프백 테스트를 통해 시험한다. 증명과 배포 사이의 간극을 측정하는 것이 목표다.

## 구현체별 비교

| implementation | fault_type | verified/n | success | failure | downgrade | negotiated group(s) |
|---|---|---|---|---|---|---|
| boringssl | binding | 10/10 | 0 | 10 | 0 | - |
| boringssl | group-list | 10/10 | 10 | 0 | 10 | X25519 |
| openssh | binding | 10/10 | 0 | 10 | 0 | sntrup761x25519-sha512@openssh.com |
| openssh | group-list | 10/10 | 10 | 0 | 10 | curve25519-sha256 |
| openssl | binding | 10/10 | 0 | 10 | 0 | - |
| openssl | group-list | 10/10 | 10 | 0 | 10 | X25519 |

## 판정

**group-list 벡터**: 세 구현(OpenSSL, BoringSSL, OpenSSH) 모두 조합당 10/10에서 하이브리드 그룹이 고전 전용 그룹으로 협상됐다 — OpenSSL/BoringSSL은 `negotiated_group=X25519`, OpenSSH는 `negotiated_group=curve25519-sha256`, 세 구현 모두 `handshake_result=success`, `downgrade_visible=true`, `manipulation_verified=true`(원자료: `docs/research/baselines/raw/phase-4/{boringssl,openssh,openssl}_group-list_r0{1..10}_default.json`). → `supported_groups` 조작에 의한 하이브리드→고전 다운그레이드 수용은 **세 독립 코드베이스 전반에 걸친 패턴**이다(단일 라이브러리의 우연한 버그가 아니다).

**binding 벡터**: 세 구현 모두 조합당 10/10에서 `handshake_result=failure`, `manipulation_verified=true`다. OpenSSL·BoringSSL은 `negotiated_group=null`(그룹이 기록되기 전에 실패), OpenSSH는 `negotiated_group=sntrup761x25519-sha512@openssh.com`(하이브리드 KEX 이름이 기록된 뒤 실패, `is_hybrid=true`)이다. 세 구현 모두 `downgrade_visible=false`다. → 결합자 바인딩 위반(PQ 성분 위조)은 세 구현 모두에서 거부되며, 어떤 구현에서도 다운그레이드로 이어지지 않는다.

**종합 판정**: 가설은 **벡터에 따라 부분적으로 지지된다**. 협상-목록 조작(group-list)에서는 세 구현 전반의 패턴이 관측됐고, 결합자 바인딩 위반(binding)에서는 세 구현 모두가 방어에 성공했다. 데이터가 뒷받침하는 것은 "이 두 결함 유형 각각에서 세 구현이 동일하게 반응한다"는 것이지, "모든 협상 결함이 다운그레이드로 이어지는 패턴"이라는 확대된 주장이 아니다 — binding 벡터는 정반대(전원 방어) 결과를 보였으므로, 결함 유형에 따라 결과가 갈린다는 점 자체가 판정의 일부다.

## Divergence와 후보 원인

**Divergence A — binding 벡터가 가설의 "다운그레이드 패턴" 기대와 반대로, 세 구현 모두에서 거부됨.**
후보 원인: 세 구현 모두 하이브리드 키 교환의 transcript/exchange-hash(또는 이에 상응하는) 바인딩이 PQ 성분 변조를 무결성 검증 단계에서 탐지해 핸드셰이크를 실패시킨다. 즉 Bhargavan et al.의 증명된-안전(proven-safe) 컴바이너 설계가, 이 벡터에 한해서는 as-deployed 구현에서도 유지된다.

**Divergence B — group-list 다운그레이드가 CVE-2026-2673의 "조용한(silent)" 특성과 달리 가시적임(`downgrade_visible=true`, 30/30).**
근거: `cd tools && python -c "import json,glob; xs=[json.load(open(f))['metrics']['downgrade_visible'] for f in glob.glob('../docs/research/baselines/raw/phase-4/*group-list*.json')]; print(sum(xs), len(xs))"` → `30 30`.
후보 원인: 본 실험의 group-list 결함은 클라이언트가 CLI에서 고전 전용 그룹 목록을 스스로 제시하는 조작이며, 결과인 고전 협상은 정상적인 프로토콜 로그에 그대로 기록된다. 반면 CVE-2026-2673은 OpenSSL의 `DEFAULT`/튜플 처리 또는 HRR(HelloRetryRequest) 내부 경로에서 발생하는 감사 우회형 조용한 폴백이다. 따라서 본 실험이 시험한 것은 "협상 로직이 고전-전용 제시를 수용하는가"이며, "그 수용이 감사 로그에서 은폐되는가"는 시험하지 못했다.

**기대/비기대 표**:

| 항목 | 기대(가설) | 관측 |
|---|---|---|
| group-list: 하이브리드→고전 다운그레이드 재현 | 재현됨 | 재현됨(3구현, 30/30) — 기대와 일치 |
| group-list: 다운그레이드의 가시성 | CVE-2026-2673처럼 조용(silent) | 가시적(`downgrade_visible=true`, 30/30) — 기대와 불일치(Divergence B) |
| binding: 다운그레이드 발생 여부 | 다운그레이드 패턴이 확장 적용될 가능성 | 전원 거부(`handshake=failure`, 0/30 다운그레이드) — 기대와 불일치(Divergence A) |

## 결론

`supported_groups` 조작에 의한 하이브리드→고전 다운그레이드는 세 독립 구현(OpenSSL, BoringSSL, OpenSSH) 모두에서 재현됐다(각 10/10, `downgrade_visible=true`, 총 30/30). 결합자 바인딩 위반은 세 구현 모두에서 거부됐다(각 10/10 `handshake_result=failure`, 다운그레이드 0/30). 따라서 "협상-목록 수준의 다운그레이드 수용"은 세 구현에 걸친 패턴으로 관측됐으나, "바인딩 위반을 통한 다운그레이드"는 본 실험의 관측 범위에서 전혀 나타나지 않았다. 가설은 두 결함 유형을 하나로 묶어 지지되지 않으며, 결함 유형별로 상반된 결과가 나왔다는 것이 이 연구의 핵심 발견이다.

## 한계

1. **group-list는 진짜 경로상(on-path) MITM 스트리핑이 아니다.** 본 실험의 group-list 조작은 클라이언트가 CLI 옵션으로 자신의 `supported_groups`를 고전 전용으로 스스로 제한하는 것이며, 공격자가 네트워크 경로에서 하이브리드 제안을 가로채 제거하는 시나리오를 재현한 것이 아니다.
2. **다운그레이드의 가시성이 CVE-2026-2673과 다르다.** 본 실험의 다운그레이드는 정상 프로토콜 로그에 그대로 기록되는 가시적(visible) 현상이며, CVE-2026-2673이 보고한 "조용한(silent)" 내부 폴백 특성은 재현되지 않았다.
3. **binding 프록시는 무결성 실패를 강제로 유도한다.** 따라서 "조용한 수용"(즉 위조된 PQ 성분이 탐지되지 않고 핸드셰이크가 성공으로 이어지는 경우)이 존재하는지는 본 실험 설계로는 관측할 수 없다 — 관측된 것은 "거부됨"뿐이며 "왜 항상 거부되는지"의 경계 조건은 확인되지 않았다.
4. **로컬 loopback, 3개 구현, 고정 버전에 한정된다.** 실배포 네트워크 환경(지연, 중간 장비, 실제 MITM 조건)이나 본 연구가 다루지 않은 다른 TLS/SSH 구현·라이브러리 버전으로 일반화할 수 없다.

자체 점검: 위 결론과 한계의 모든 문장은 `docs/research/baselines/raw/phase-4/`의 60개 JSON과 `manifest.csv`에 기록된 `negotiated_group`, `handshake_result`, `downgrade_visible`, `manipulation_verified` 값에서 직접 도출되었으며, 원시 데이터에 없는 주장(예: 실배포 일반화, CVE와의 동일시, binding의 잠재적 우회 가능성)은 포함하지 않았다.
