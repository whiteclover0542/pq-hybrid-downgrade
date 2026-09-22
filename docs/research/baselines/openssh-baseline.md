# OpenSSH 정상 hybrid KEX baseline

## 판정

- [확실] 고정 OpenSSH portable client와 loopback `sshd` 간 public-key authenticated connection이 성공했습니다.
- [확실] client `-vvv` 원시 로그는 `kex: algorithm: sntrup761x25519-sha512@openssh.com`을 기록합니다.
- [확실] host-key algorithm은 `ssh-ed25519`이고, 인증 결과는 `Authenticated to 127.0.0.1 ... using "publickey"`입니다.

## 고정 대상 및 명령

- [확실] OpenSSH portable tag `V_10_2_P1`, checkout `d01efaa1c9ed84fd9011201dbc3c7cb0a82bcee3`.
- [확실] `autoreconf` 뒤 custom OpenSSL include/lib 경로를 주입해 빌드했습니다. 실행 시에도 `LD_LIBRARY_PATH=/root/pq-hybrid-phase2/install/openssl/lib64`를 사용했습니다.
- [확실] loopback `sshd`는 127.0.0.1:2222만 listen했고, `KexAlgorithms sntrup761x25519-sha512@openssh.com` 및 일회성 test key만 사용했습니다.
- [확실] client는 `ssh -vvv -o KexAlgorithms=sntrup761x25519-sha512@openssh.com ... root@127.0.0.1 true`로 실행했습니다.

## 원자료

| 파일 | SHA-256 | 용도 |
|---|---|---|
| `raw/openssh-d01efaa1-baseline-client.log` | `427fc965b0fad02d1931ae01ad2539139215849d6f54ec49f2990417daee3667` | KEX·인증 verbose log |
| `raw/openssh-d01efaa1-baseline-server.log` | `bc5d98f4948f95d0942c2a0b6721535a644eb23d128e757448fa02c68f2d20e8` | server audit log |
| `raw/openssh-d01efaa1-baseline.pcapng` | `ee3b631414faa797da06376b5214c43c25dab6c4b5cd96a8f699e9a8f2853b4e` | loopback packet capture |

- [확실] pcap 요약은 39 frame/9,818 byte 중 SSH 25 frame/8,690 byte를 보고했습니다.
