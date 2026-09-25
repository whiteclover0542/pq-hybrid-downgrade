---
phase: 07-v11-tooling
plan: 01
status: complete
completed: 2026-09-25
---

# v1.1-P1 도구 확장 완료 및 P2 인계

## 완료 판정

| 성공 기준 | 판정 | 근거 |
|---|---|---|
| v1.0 JSON 하위 호환 | 충족 | `Metrics`의 v1.1 필드는 기본값을 가지며, 실제 v1.0 phase-4 JSON을 읽는 회귀 테스트가 통과한다. |
| HRR·감사 가시성 파서 | 충족 | 스파이크 로그 형식의 `HelloRetryRequest` 및 ServerHello 길이로 단위 테스트한다. |
| base / silent-downgrade / ssh-order 조건 | 충족 | 조건 빌더와 v1.1 조합 테스트가 각 조건의 명령·순서를 확인한다. |
| on-path strip 조작 | 충족 | TLS ClientHello와 SSH KEXINIT에서 하이브리드 알고리즘을 제거하고 길이를 갱신하는 단위 테스트가 있다. |
| 유효 조합만 실행 | 충족 | `v11_specs(1)`은 아래 9개 조합만 만들고, 반복 수에 비례해 확장된다. |
| 전체 회귀 | 충족 | `tools/`에서 `python -m pytest -q` 결과 63 passed, 1 skipped였다. Windows의 TShark 의존 테스트 1건은 환경상 skip된다. |

## P2 실행 인계

P2는 WSL Ubuntu에서 다음 명령으로 시작한다. 이 명령은 사전 점검 후 각 조합을 10회 실행하고, 원시 산출물을 `docs/research/baselines/raw/v1.1/`에 기록한다.

```powershell
wsl -d Ubuntu -u root -- bash -lc 'cd /mnt/d/IT/git/PERSONAL/pq-hybrid-downgrade/pq-hybrid-downgrade/tools && python3 -m faultinject.run --v11 10'
```

### 실행 조합과 표본 설계

반복 1회당 9개 조합, 조합당 10회 이상을 수집한다.

| 구현 | 조건 | 조작/의도 |
|---|---|---|
| OpenSSL | base | 하이브리드 우선 대조군 |
| OpenSSL | silent-downgrade | 하이브리드 광고 + 고전 key_share 우선 |
| OpenSSL | onpath-strip | ClientHello의 하이브리드 그룹 제거 |
| BoringSSL | base | 하이브리드 우선 대조군 |
| BoringSSL | silent-downgrade | 하이브리드 광고 + 고전 key_share 우선 |
| BoringSSL | onpath-strip | ClientHello의 하이브리드 그룹 제거 |
| OpenSSH | base | 하이브리드 우선 대조군 |
| OpenSSH | ssh-order | KEX 알고리즘 순서 대조군 |
| OpenSSH | onpath-strip | KEXINIT의 하이브리드 KEX 제거 |

### P2에서 기록·판정할 지표

각 실행에는 다음 값을 기록한다.

1. 핸드셰이크 결과와 협상 그룹
2. `hrr_present`
3. `advertised_hybrid`와 `downgrade_flagged`
4. `manipulation_verified`

`silent-downgrade`는 PCAP의 ClientHello에서 하이브리드 그룹 ID가 advertised group에 있고, 첫 `key_share`가 고전 그룹 `0x001d`인 경우에만 조작 적용으로 판정한다. OpenSSL은 `0x11ec`, BoringSSL은 `0x6399`를 하이브리드 그룹으로 사용한다. `onpath-strip`은 프록시 로그의 `strip_mutation`과 조작 전후 SHA-256 차이가 모두 있어야 적용으로 판정한다.

## 실행 전 확인 사항

- WSL Ubuntu에 TShark가 설치되어 있어야 한다.
- `phase2_paths()`가 가리키는 `/root/pq-hybrid-phase2`의 세 구현체 바이너리와 OQS provider가 있어야 한다.
- P2를 시작하기 전 `python3 -m faultinject.run --v11 1`로 프리플라이트와 한 반복을 먼저 확인할 수 있다. 이 사전 실행도 연구 데이터로 보존한다.

## 범위 경계

이 문서는 도구와 단위·파서 검증의 완료 기록이다. P2의 실제 협상 결과나 다운그레이드 관측 결과는 아직 기록하지 않는다.
