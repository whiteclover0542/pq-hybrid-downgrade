---
phase: 02-testbed
status: passed
verified: 2026-09-22
requirement: REQ-testbed-three-implementations
---

# Phase 2 검증 보고서

## 최종 판정

- [확실] **passed** — Phase 2의 목표와 `REQ-testbed-three-implementations`의 필수 조건을 실제 원시 증적으로 확인했습니다.

## Must-have 대조

| 성공 기준 | 판정 | 실제 근거 |
|---|---|---|
| 세 구현체의 조작 없는 hybrid handshake | [확실] 통과 | OpenSSL TLS 1.3, BoringSSL TLS 1.3, OpenSSH loopback public-key handshake가 각각 성공 로그를 남겼습니다. |
| 협상 group/KEX의 로그 관측 | [확실] 통과 | OpenSSL `Negotiated TLS1.3 group: X25519MLKEM768`; BoringSSL `ECDHE group: X25519Kyber768Draft00`; OpenSSH `kex: algorithm: sntrup761x25519-sha512@openssh.com`. |
| 버전·커밋·빌드 옵션 기록 | [확실] 통과 | `docs/research/phase-2-environment.md`에 OpenSSL/liboqs/oqs-provider/BoringSSL/OpenSSH의 fixed ref, checkout, 핵심 옵션을 기록했습니다. |
| 감사·로깅 경로 4종 | [확실] 통과 | OpenSSL state log, TLS keylog, OpenSSH `-vvv`, 모든 구현체의 loopback pcapng를 보관했습니다. |

## 증적 무결성

- [확실] 세 baseline 문서가 기록한 SHA-256은 `raw/` 원자료의 재계산값과 일치합니다.
- [확실] OpenSSL keylog는 5개 TLS traffic secret 항목을 포함하며, client/server log에는 handshake 완료 및 shared group 기록이 있습니다.
- [확실] `tshark -r ... -z io,phs`로 pcap을 직접 재검증했습니다: OpenSSL은 TLS 7 frame/4,994 byte, BoringSSL은 TLS 4 frame/4,053 byte, OpenSSH는 SSH 25 frame/8,690 byte입니다.
- [확실] pcap은 payload만으로 PQ group/KEX를 판독하는 근거로 쓰지 않았습니다. group/KEX 판정은 각 구현체의 client log에서, pcap은 독립적 네트워크 증적으로 사용했습니다.

## BoringSSL 명칭 판정

- [확실] 계획은 `X25519Kyber768`을 요구하지만 고정 BoringSSL commit의 도구 출력은 `X25519Kyber768Draft00`입니다.
- [확실] source와 baseline 문서는 TLS code point `0x6399` 및 해당 명칭 차이를 함께 기록합니다. 따라서 실제 evidence를 계획 표기로 부정확하게 덮어쓰지 않았고, Kyber hybrid 대상의 관측 조건은 충족합니다.

## 요구사항 추적

- [확실] `REQ-testbed-three-implementations`는 `.planning/REQUIREMENTS.md`에서 Complete로 표시됐고, 세 독립 코드베이스의 actual build·정상 hybrid baseline·재현 정보가 모두 존재합니다.

## Human Verification

- [확실] 추가 human verification은 필요하지 않습니다. 모든 Phase 2 성공 기준은 명령 출력과 저장된 원자료로 자동 검증됐습니다.
