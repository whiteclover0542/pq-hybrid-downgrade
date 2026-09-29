# pq-hybrid-downgrade

포스트퀀텀 하이브리드 키 교환의 다운그레이드 저항성이 OpenSSL, BoringSSL, OpenSSH 구현에서 증명대로 성립하는지 측정한 연구입니다. 경로상 조작(v1.0·v1.1)과 공격자 없는 협상 정책(v1.1)을 비교했고, 후자의 결함 사례로 CVE-2026-2673을 재현하고(v1.2) 인과를 분리했습니다(v1.3).

| 목적 | 문서·자료 |
|---|---|
| 연구 동기(착수 시점 기획) | [연구 기획서](docs/PROPOSAL.md) |
| 결론과 한계 | [논문](docs/PAPER.md) |
| 표본·환경·근거 | [근거 대장](docs/EVIDENCE.md) |
| 재현 명령 | [재현 안내](docs/research/REPRODUCTION.md) |
| 원시 데이터 | [v1.3 120회](docs/research/baselines/raw/v1.3/) · [v1.2 60회](docs/research/baselines/raw/v1.2/) · [v1.1 90회](docs/research/baselines/raw/v1.1/) · [v1.0 60회](docs/research/baselines/raw/phase-4/) |
| 재현 패키지 | [dist/](dist/) |

[확실] 단계별 계획·완료 기록·중간 분석은 Git 이력에만 보존합니다. 현재 작업 트리의 문서는 위 표의 진입점으로 제한합니다.

코드와 테스트는 [tools/faultinject/](tools/faultinject/)에 있으며 `cd tools && python -m pytest`로 확인합니다.
