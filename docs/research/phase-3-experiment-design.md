# Phase 3 실험 설계

## 목적과 경계

- [확실] 이 도구는 WSL2의 `127.0.0.1` loopback 안에서만 실행합니다.
- [확실] Phase 2에서 고정한 바이너리·커밋·환경 변수·감사 경로만 사용합니다.
- [확실] 외부 호스트·실네트워크·미승인 대상에는 연결하거나 조작하지 않습니다.

## 실험 변수

| 구분 | 값 |
| --- | --- |
| 구현체 | OpenSSL, BoringSSL, OpenSSH |
| 결함 유형 | `group-list`, `binding` |
| 고정 요인 | 하이브리드 그룹 설정, loopback 네트워크, Phase 2와 같은 로그·pcap 감사 경로 |

## 기준 협상값

| 구현체 | 정상 하이브리드 협상값 |
| --- | --- |
| OpenSSL | `X25519MLKEM768` |
| BoringSSL | `X25519Kyber768Draft00` (`0x6399`) |
| OpenSSH | `sntrup761x25519-sha512@openssh.com` |

## 결함 주입 지점

| 결함 | 개입 지점 | 의미 |
| --- | --- | --- |
| `group-list` | 클라이언트 CLI의 그룹/KEX 목록 | 하이브리드 그룹을 제외한 제안을 보냅니다. |
| `binding` | loopback MITM 프록시의 TLS `key_share` 또는 SSH `KEX_ECDH_INIT` | 하이브리드 교환의 PQ 성분 바이트만 위조합니다. |

## 실행별 관측 지표

1. [확실] **협상 결과 그룹**: client log에서 읽은 최종 그룹 문자열과 `is_hybrid`를 기록합니다.
2. [확실] **감사 경로 가시성**: client log의 협상 줄, OpenSSL `-state`, OpenSSH `-vvv`, keylog, pcap에서 classical-only 협상이 드러나는지를 `downgrade_visible`로 기록합니다.
3. [확실] **핸드셰이크 결과**: 종료 코드와 구현체별 성공 마커를 합쳐 `success` 또는 `failure`로 기록합니다.

## 조작 적용 판정

- [확실] `manipulation_verified=true`은 조작 바이트 또는 그룹 목록 변경이 실제 통신에 반영됐다는 뜻입니다.
- [확실] `manipulation_verified=false`인 실행은 도구가 조작을 적용하지 못했을 수 있으므로 보존하되, 취약성 판정 표본과 분리합니다.
- [확실] 조작 뒤 연결이 실패하는 것은 결과 데이터이며, 프록시 파싱 실패와 구현체의 거부는 별도로 검증합니다.

## 원시 데이터 규칙

- [확실] 실행 ID는 `<impl>_<fault>_r<NN>_<condition>` 형식을 사용합니다.
- [확실] 예시는 `boringssl_binding_r03_default`입니다.
- [확실] 각 실행의 client/server log, pcap, JSON 레코드를 삭제하지 않고 함께 보존합니다.
