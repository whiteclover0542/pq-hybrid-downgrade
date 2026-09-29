# pq-hybrid-downgrade

OpenSSL `DEFAULT` group 설정의 CVE-2026-2673을 OpenSSL 3.5.5/3.5.6 대조로 재현한 연구입니다. 현재 주 결과는 v1.2입니다.

| 목적 | 문서·자료 |
|---|---|
| 연구 동기(착수 시점 기획) | [연구 기획서](docs/PROPOSAL.md) |
| 결론과 한계 | [논문](docs/PAPER.md) |
| 표본·환경·근거 | [근거 대장](docs/EVIDENCE.md) |
| 재현 명령 | [재현 안내](docs/research/REPRODUCTION.md) |
| 원시 데이터 | [v1.2 60회](docs/research/baselines/raw/v1.2/) · [v1.1 90회](docs/research/baselines/raw/v1.1/) |
| 재현 패키지 | [dist/](dist/) |

[확실] 단계별 계획·완료 기록·중간 분석은 Git 이력에만 보존합니다. 현재 작업 트리의 문서는 위 표의 진입점으로 제한합니다.

코드와 테스트는 [tools/faultinject/](tools/faultinject/)에 있으며 `cd tools && python -m pytest`로 확인합니다.
