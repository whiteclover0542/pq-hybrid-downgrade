---
phase: 02-testbed
plan: 01
subsystem: testing
tags: [openssl, oqs-provider, liboqs, boringssl, openssh, hybrid-kem, wsl2, tshark]
requires:
  - phase: 01-literature
    provides: CVE-2026-2673 영향 범위와 Phase 2 대상 구현체·관측 조건
provides:
  - 세 독립 구현체의 고정 source checkout·빌드 옵션
  - 조작 없는 hybrid TLS/SSH loopback baseline과 원시 증적
  - Phase 3 fault-injector의 협상 관측점과 비교 기준
affects: [03-fault-injector, 04-downgrade-experiments, 05-analysis]
tech-stack:
  added: [WSL2 Ubuntu, CMake, Ninja, Go, TShark, liboqs, oqs-provider]
  patterns: [absolute built-binary paths, explicit dynamic-library paths, loopback-only baseline capture]
key-files:
  created:
    - docs/research/phase-2-environment.md
    - docs/research/baselines/openssl-baseline.md
    - docs/research/baselines/boringssl-baseline.md
    - docs/research/baselines/openssh-baseline.md
    - docs/research/baselines/raw/
  modified:
    - .planning/phases/02-testbed/02-01-PLAN.md
key-decisions:
  - "WSL2 Ubuntu를 단일 재현 환경으로 고정했다."
  - "OpenSSL 3.5.5를 CVE-2026-2673 수정 전 대상 버전으로 고정했다."
  - "BoringSSL의 실제 출력 이름 X25519Kyber768Draft00과 계획의 축약 표기를 모두 보존했다."
patterns-established:
  - "baseline은 실제 협상 group/KEX가 들어 있는 client log와 pcap을 함께 보관한다."
  - "custom OpenSSL은 절대 경로, LD_LIBRARY_PATH, OPENSSL_MODULES를 모두 명시해 시스템 라이브러리 혼입을 막는다."
requirements-completed: [REQ-testbed-three-implementations]
duration: 1h 40m
completed: 2026-09-22
---

# Phase 2 Plan 01: Testbed Summary

**OpenSSL+oqs-provider, BoringSSL, OpenSSH의 고정 빌드와 조작 없는 세 하이브리드 협상 baseline을 원시 로그·pcap으로 확보했습니다.**

## Performance

- **Duration:** 1h 40m
- **Started:** 2026-09-22T10:40:00Z
- **Completed:** 2026-09-22T12:20:00Z
- **Tasks:** 6/6
- **Files modified:** 15

## Accomplishments

- OpenSSL 3.5.5, liboqs 0.14.0, oqs-provider 0.9.0을 고정하고 `X25519MLKEM768` TLS 1.3 handshake 및 active provider를 검증했습니다.
- Kyber hybrid group을 포함한 BoringSSL 고정 커밋을 GCC 15 호환 옵션으로 빌드하고 `X25519Kyber768Draft00` 협상을 검증했습니다.
- OpenSSH 10.2p1을 custom OpenSSL과 빌드하고 `sntrup761x25519-sha512@openssh.com` KEX와 공개키 인증을 검증했습니다.
- 세 baseline에 대해 client/server log와 loopback pcap을 보관하고, OpenSSL TLS keylog도 별도 보관했습니다.

## Task Commits

1. **Task 1·5: 환경 대장, 감사 경로, 원자료 정리** — `bbf4c99` (`docs`)
2. **Task 2: OpenSSL + oqs-provider baseline** — `daadf13` (`feat`)
3. **Task 3: BoringSSL baseline** — `ac88fca` (`feat`)
4. **Task 4: OpenSSH hybrid KEX baseline** — `ed2e008` (`feat`)
5. **Task 6: 계획 완료 및 phase 추적 갱신** — 이 summary의 metadata commit

## Files Created/Modified

- `docs/research/phase-2-environment.md` — 환경·고정 source·감사 경로·Phase 3 인계 대장
- `docs/research/baselines/openssl-baseline.md` — OpenSSL provider/group/keylog baseline
- `docs/research/baselines/boringssl-baseline.md` — BoringSSL Kyber group baseline
- `docs/research/baselines/openssh-baseline.md` — OpenSSH hybrid KEX baseline
- `docs/research/baselines/raw/` — 로그, pcapng, OpenSSL keylog 원자료

## Decisions Made

- [확실] WSL2 Ubuntu를 선택했습니다. 세 구현체와 packet capture를 한 환경에서 재현할 수 있기 때문입니다.
- [확실] OpenSSL 3.5.5를 선택했습니다. 프로젝트의 CVE 분석 노트가 기록한 3.5.0~3.5.5 영향 범위 안이며 3.5.6 수정 릴리스 이전입니다.
- [확실] BoringSSL의 실제 handshake 출력인 `X25519Kyber768Draft00` 및 source의 `0x6399`를 기록했습니다. 계획의 `X25519Kyber768` 표기와 혼동하지 않기 위해서입니다.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] WSL 빌드 도구 부재**
- **Found during:** Task 1
- **Issue:** CMake, Ninja, Go, compiler, TShark, Autotools가 설치돼 있지 않았습니다.
- **Fix:** 필요한 Ubuntu 표준 패키지를 설치하고 버전을 환경 대장에 기록했습니다.
- **Verification:** 각 도구의 `--version`과 실제 빌드·캡처 성공을 확인했습니다.

**2. [Rule 3 - Blocking] BoringSSL의 GCC 15 warning-as-error 호환성**
- **Found during:** Task 3
- **Issue:** 고정 2024 BoringSSL commit이 `OPENSSL_memchr`의 const-qualifier 경고를 오류로 승격했습니다.
- **Fix:** source 변경 없이 `-Wno-error=discarded-qualifiers`만 CMake C flags에 추가했습니다.
- **Verification:** `bssl` 빌드와 `X25519Kyber768Draft00` handshake가 성공했습니다.

**3. [Rule 3 - Blocking] OpenSSH configure 재생성과 sshd test 계정**
- **Found during:** Task 4
- **Issue:** source timestamp로 `autoreconf`가 필요했고, loopback sshd에는 비로그인 `sshd` privilege-separation 계정이 필요했습니다.
- **Fix:** Autotools를 설치하고 configure를 재생성했으며 Ubuntu에 비로그인 시스템 계정 하나를 만들었습니다.
- **Verification:** custom `ssh`/`sshd` 10.2p1과 목표 KEX를 확인하고 loopback public-key connection을 성공시켰습니다.

---

**Total deviations:** 3 auto-fixed (3 blocking environment/compatibility items).
**Impact on plan:** 모두 실제 빌드와 정상 baseline을 가능하게 한 최소 환경 조정이며, 결함 주입·프로토콜 동작 변경·범위 확장은 없습니다.

## Issues Encountered

None remaining. OpenSSL 서버의 표준입력이 EOF일 때 조기 종료되는 현상은 `tail -f /dev/null`로 표준입력을 유지해 해결했고, 정상 협상 로그로 재검증했습니다.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- [확실] Phase 3은 세 implementation의 실제 협상 관측점과 저장된 baseline log/pcap을 비교 기준으로 사용할 수 있습니다.
- [확실] Phase 3의 실행 전에는 custom binary absolute path, `LD_LIBRARY_PATH`, `OPENSSL_MODULES`, OpenSSH KEX 강제 옵션을 다시 검증해야 합니다.

---
*Phase: 02-testbed*
*Completed: 2026-09-22*
