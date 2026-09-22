# Phase 3 완료 요약 — 실험 도구 개발

완료일: 2026-09-23

## 완료 근거

- [확실] `tools/faultinject/`에 세 구현체용 `group-list` 및 `binding` 시나리오, loopback 전용 프록시, 지표 수집 하네스, 적용 검증기를 구현했습니다.
- [확실] `python -m faultinject.run --smoke`로 3개 구현체 × 2개 결함 경로를 각 1회 실행했습니다.
- [확실] `group-list` 3개는 고전 그룹/KEX와 성공한 연결을 기록했고 `manipulation_verified=true`입니다.
- [확실] `binding` 3개는 프록시 로그의 변경 전후 해시로 조작 적용을 확인했고 `manipulation_verified=true`입니다. 이 실행들의 연결 실패는 조작 적용 실패와 별도로 기록됩니다.
- [확실] 전체 테스트는 `python3 -m pytest faultinject/tests -q`에서 31개 통과했습니다.

## 원시 결과 위치

- [확실] 실행별 JSON·클라이언트/서버 로그·pcap·캡처 로그는 `docs/research/baselines/raw/phase-3/`에 있습니다.
- [확실] binding 실행에는 조작 적용 근거인 `*-proxy.log`가 추가됩니다.

## Phase 4 인계

- [확실] 반복 횟수는 구현체 × 결함 경로 조합당 최소 10회입니다.
- [확실] `manipulation_verified=false`인 실행은 원시 파일을 보존하되 결론 표본으로 사용하지 않습니다.
- [확실] 반복 실행에서도 Phase 2의 고정 바이너리 절대 경로와 환경 변수를 유지해야 합니다.
