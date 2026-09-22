# Phase 2 테스트베드 환경 대장

## 실행 환경

- [확실] 실행 일자: 2026-09-22 (KST).
- [확실] 빌드 환경: WSL2의 Ubuntu 26.04.1 LTS, 커널 `6.6.87.2-microsoft-standard-WSL2`, x86_64.
- [확실] 선택 이유: 세 구현체 모두 Linux 빌드 문서와 도구 체인이 성숙해 있고, loopback 서버·클라이언트 및 `tshark` 캡처를 같은 격리 환경에서 재현할 수 있습니다.
- [확실] 모든 소스·설치물은 WSL의 `/root/pq-hybrid-phase2`에 두었습니다. baseline 실행은 절대 경로의 빌드 바이너리와 명시적 `LD_LIBRARY_PATH`를 사용했습니다.

## 도구 체인

| 도구 | 확인된 버전 |
|---|---|
| Git | 2.53.0 |
| CMake | 4.2.3 |
| Ninja | 1.13.2 |
| Go | 1.26.0 |
| Perl | 5.40.1 |
| GCC | 15.2.0 |
| TShark | 4.6.4 |

## 고정 소스와 빌드

| 구현체 | 고정 ref / checkout | 빌드 핵심 옵션 | 목표 group/KEX |
|---|---|---|---|
| OpenSSL | `openssl-3.5.5`, checkout `67b5686b4419b4cb8caa502711c41815f5279751` | `./Configure linux-x86_64 --prefix=/root/pq-hybrid-phase2/install/openssl --openssldir=.../ssl no-tests`; `make -j2 install_sw` | `X25519MLKEM768` |
| liboqs | `0.14.0`, `94b421ebb82405c843dba4e9aa521a56ee5a333d` | CMake Release shared build, prefix `.../install/liboqs` | oqs-provider 의존성 |
| oqs-provider | `0.9.0`, `848b4e6abaa89e769c4db46ca78f91000f67ca52` | CMake Release; 위 OpenSSL 및 liboqs 경로를 명시 | `X25519MLKEM768` |
| BoringSSL | `7fb4d3da5082225c7180267e9daad291887ce982` (2024-08-27) | CMake/Ninja Release; GCC 15 호환을 위해 `-Wno-error=discarded-qualifiers`만 추가 | `X25519Kyber768Draft00` (별칭·연구 표기: `X25519Kyber768`, code point `0x6399`) |
| OpenSSH portable | `V_10_2_P1`, checkout `d01efaa1c9ed84fd9011201dbc3c7cb0a82bcee3` | `autoreconf`; custom OpenSSL include/lib를 지정한 `./configure`; `make -j2 install-nokeys` | `sntrup761x25519-sha512@openssh.com` |

## OpenSSL 취약 대상 선택

- [확실] OpenSSL 3.5.5는 프로젝트의 CVE-2026-2673 분석 노트가 기록한 영향 범위(3.5.0~3.5.5)에 포함되고, 수정이 포함된 3.5.6 이전입니다. 따라서 Phase 4의 수정 전 재현 대상이라는 제약을 만족합니다.
- [확실] 실행 시 `LD_LIBRARY_PATH=/root/pq-hybrid-phase2/install/openssl/lib64:/root/pq-hybrid-phase2/install/liboqs/lib` 및 `OPENSSL_MODULES=.../ossl-modules`를 설정했습니다. `openssl list -providers -provider default -provider oqsprovider`에서 `oqsprovider` 0.9.0이 active였고, `openssl list -all-tls-groups`에서 `X25519MLKEM768`을 확인했습니다.

## 감사·로깅 경로

| 경로 | 확인 방법 | 원자료 |
|---|---|---|
| TLS 협상 상태 | OpenSSL `s_client -state`, BoringSSL `bssl client` | 각 client/server log |
| TLS key log | OpenSSL `s_client -keylogfile` | `openssl-67b5686b-client.keys` |
| SSH KEX | OpenSSH `ssh -vvv` | `openssh-d01efaa1-baseline-client.log` |
| 패킷 | loopback `tshark -i lo` | 각 `.pcapng` |

## 재현 경계

- [확실] 모든 handshake는 `127.0.0.1` loopback에서 수행했고, 결함 주입·중간자·패킷 조작은 하지 않았습니다.
- [확실] BoringSSL의 고정 커밋은 연구 계획의 축약 표기 `X25519Kyber768`에 대응하는 실제 TLS 이름 `X25519Kyber768Draft00`을 출력합니다. 두 표기를 같은 것으로 조용히 치환하지 않고 baseline 문서에 함께 보존했습니다.

## Phase 3 인계 조건

- [확실] Fault Injector는 각 구현체의 실제 협상 관측점만 바꿔야 합니다: OpenSSL의 `X25519MLKEM768`, BoringSSL의 `X25519Kyber768Draft00`/`0x6399`, OpenSSH의 `sntrup761x25519-sha512@openssh.com`.
- [확실] 비교 기준은 본 문서에 고정된 버전·커밋·빌드 옵션, 각 baseline client log, 그리고 각 loopback pcap입니다.
- [확실] Phase 3 시작 전에는 custom OpenSSL의 `LD_LIBRARY_PATH` 및 `OPENSSL_MODULES`, OpenSSH의 절대 경로와 KEX 강제 옵션을 다시 확인해야 합니다. 시스템 기본 바이너리로 바뀌면 비교 결과가 무효입니다.
- [확실] Phase 2의 네 성공 기준(세 정상 hybrid handshake, 각 group/KEX의 로그 관측, 버전·커밋·빌드 옵션 기록, 네 감사 경로 확인)을 모두 충족했으므로 Phase 3을 시작할 수 있습니다.
