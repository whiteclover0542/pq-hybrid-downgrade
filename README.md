# pq-hybrid-downgrade

포스트퀀텀 하이브리드 키 교환의 다운그레이드 저항성이 실제 구현(OpenSSL, BoringSSL, OpenSSH, Go, NSS, rustls)에서 증명대로 성립하는지 측정한 연구입니다. 공격자가 결과를 끌어내리는 다운그레이드(경로상 조작, v1.0·v1.1)와 공격자 없이 하이브리드가 빠지는 PQ 누락(협상 함수)을 구분해 측정했습니다. PQ 누락 쪽에서는 CVE-2026-2673을 재현하고(v1.2) 인과를 분리했으며(v1.3), 다섯 TLS 구현의 협상 함수를 비교하고(v1.5) 기본 설정의 클라이언트와 nginx·Caddy를 조사했습니다(v1.6). v1.7에서는 headless 브라우저 두 개의 ClientHello, 상세 감사 출력, OpenSSL 3.6 인과 분리를 보완했습니다.

| 목적 | 문서·자료 |
|---|---|
| 연구 동기(착수 시점 기획) | [연구 기획서](docs/PROPOSAL.md) |
| 결론과 한계 | [논문](docs/PAPER.md) |
| 표본·환경·근거 | [근거 대장](docs/EVIDENCE.md) |
| 재현 명령 | [재현 안내](docs/research/REPRODUCTION.md) |
| 원시 데이터 | [v1.7 15회](docs/research/baselines/raw/v1.7/) · [v1.7 3.6 인과 분리 60회](docs/research/baselines/raw/v1.7-openssl36/) · [v1.6 36회](docs/research/baselines/raw/v1.6/) · [v1.5 105회](docs/research/baselines/raw/v1.5/) · [v1.4 60회](docs/research/baselines/raw/v1.4/) · [v1.3 120회](docs/research/baselines/raw/v1.3/) · [v1.2 60회](docs/research/baselines/raw/v1.2/) · [v1.1 90회](docs/research/baselines/raw/v1.1/) · [v1.0 60회](docs/research/baselines/raw/phase-4/) |
| 재현 패키지 | [dist/](dist/) |

[확실] 단계별 계획·완료 기록·중간 분석은 Git 이력에만 보존합니다. 현재 작업 트리의 문서는 위 표의 진입점으로 제한합니다.

코드와 테스트는 [tools/faultinject/](tools/faultinject/)에 있으며 `cd tools && python -m pytest`로 확인합니다.
