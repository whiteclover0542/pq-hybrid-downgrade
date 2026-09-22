# OpenSSL + oqs-provider 정상 baseline

## 판정

- [확실] 정상 TLS 1.3 handshake가 성공했습니다.
- [확실] 클라이언트 원시 로그는 `Negotiated TLS1.3 group: X25519MLKEM768`을 기록합니다.
- [확실] active provider는 OpenSSL Default Provider 3.5.5와 OpenSSL OQS Provider 0.9.0입니다.
- [확실] 협상 cipher는 `TLS_AES_256_GCM_SHA384`입니다.

## 고정 대상 및 명령

- [확실] OpenSSL: `openssl-3.5.5`, `67b5686b4419b4cb8caa502711c41815f5279751`.
- [확실] liboqs: 0.14.0 (`94b421ebb82405c843dba4e9aa521a56ee5a333d`); oqs-provider: 0.9.0 (`848b4e6abaa89e769c4db46ca78f91000f67ca52`).
- [확실] server/client는 설치된 절대 경로의 `openssl`을 사용했고, `-tls1_3 -groups X25519MLKEM768 -provider default -provider oqsprovider -state`를 지정했습니다.
- [확실] client에는 `-keylogfile`를 지정했습니다. 이 파일은 TLS 복호화가 필요한 후속 분석을 위한 민감한 연구 증적이므로 저장소 밖으로 전송하지 않았습니다.

## 원자료

| 파일 | SHA-256 | 용도 |
|---|---|---|
| `raw/openssl-67b5686b-baseline-client.log` | `4b0c0d4ed29393f7e355bdbe258aa9c880e6f7e8b27fd6ad25a99646f76323bc` | group·cipher·state |
| `raw/openssl-67b5686b-baseline-server.log` | `488a86a4f7c039184caf91f76b857bf57be43d1fecdd54df6f70d80ef55a114c` | server state |
| `raw/openssl-67b5686b-client.keys` | `617d342d0ef47a33619d22941197d096856d6d1001d28c5911ae1a5b59c868af` | TLS key log |
| `raw/openssl-67b5686b-baseline.pcapng` | `ca02ba2026981506283a7dbd7c8d8e6b641a3b8d28a0adbb8253f77fba91ab22` | loopback packet capture |

- [확실] `tshark -r ... -z io,phs`는 16 frame/5,604 byte 중 TLS 7 frame/4,994 byte를 보고했습니다.
