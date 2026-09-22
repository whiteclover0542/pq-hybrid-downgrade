# BoringSSL 정상 baseline

## 판정

- [확실] 고정 BoringSSL `bssl server`와 `bssl client` 간 정상 TLS 1.3 handshake가 성공했습니다.
- [확실] client 원시 로그는 `ECDHE group: X25519Kyber768Draft00`을 기록합니다.
- [확실] 이 commit의 소스에는 `CurveX25519Kyber768 = 0x6399`도 존재합니다. 계획의 `X25519Kyber768` 표기는 이 역사적 Kyber hybrid 계열을 가리키며, 실제 도구 출력 이름은 Draft00입니다.
- [확실] 협상 cipher는 `TLS_AES_128_GCM_SHA256`입니다.

## 고정 대상 및 명령

- [확실] checkout: `7fb4d3da5082225c7180267e9daad291887ce982`.
- [확실] CMake Release/Ninja로 `tool/bssl`을 빌드했습니다. GCC 15의 const-qualifier 경고만 `-Wno-error=discarded-qualifiers`로 오류 승격에서 제외했습니다.
- [확실] loopback server/client에는 `-curves X25519Kyber768Draft00 -min-version tls1.3 -max-version tls1.3`를 지정했습니다.

## 원자료

| 파일 | SHA-256 | 용도 |
|---|---|---|
| `raw/boringssl-7fb4d3da-baseline-client.log` | `4a651cdc480b6afe95f395b1266e676bdbb89df9e20a0ad9110042b3bc1cc8ca` | group·cipher·connection |
| `raw/boringssl-7fb4d3da-baseline-server.log` | `5e530eb05074c76c658287f81f830deddf0eb24d696addb98b524ac6c3ca4986` | server connection |
| `raw/boringssl-7fb4d3da-baseline.pcapng` | `34a9b7c7ae96e7ab6238c500fa8f8db58caa75152c669839935e214b2416797b` | loopback packet capture |

- [확실] pcap 요약은 12 frame/4,597 byte 중 TLS 4 frame/4,053 byte를 보고했습니다.
