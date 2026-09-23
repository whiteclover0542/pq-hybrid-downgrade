# 협상 로직 결함에 의한 하이브리드-PQ 다운그레이드: 교차 구현 재현 연구

- 저자: whiteclover0542
- 날짜: 2026-09-23
- 한 줄 요약: 세 독립 TLS/SSH 구현(OpenSSL, BoringSSL, OpenSSH)에서 협상-목록 조작과 컴바이너 바인딩 위반을 통제 실험으로 재현해, 증명된-안전(proven-safe) 하이브리드-PQ 설계와 실제 배포 구현의 거동 사이 간극을 측정한다.

---

## 초록

## 1. 서론

## 2. 방법

## 3. 결과

## 4. 논의

## 참고문헌

[1] Karthikeyan Bhargavan, Christina Brzuska, Cédric Fournet, Matthew Green, Markulf Kohlweiss, Santiago Zanella-Béguelin, "Downgrade Resilience in Key-Exchange Protocols," IEEE Symposium on Security and Privacy (S&P), 2016. https://www.microsoft.com/en-us/research/publication/downgrade-resilience-in-key-exchange-protocols/

[2] Bhanwar Gupta, Sanjeev Rana, "Transcript-Bound Combiners for Downgrade-Resilient Hybrid Post-Quantum Key Establishment: Definition, Proof, and Embedded-Device Cost," arXiv:2609.21273, 2026-09-18. https://arxiv.org/abs/2609.21273

[3] CVE-2026-2673 — OpenSSL Security Advisory, 2026-03-13; CVE Record. https://openssl-library.org/news/secadv/20260313.txt , https://www.cve.org/CVERecord?id=CVE-2026-2673

[4] CVE-2026-91949 — FreeRDP protocol-negotiation policy bypass (background). NVD. https://nvd.nist.gov/vuln/detail/CVE-2026-91949

[5] CVE-2026-20249 — Cisco ASA/FTD IKEv2 authentication-stage logic error (background). NVD. https://nvd.nist.gov/vuln/detail/CVE-2026-20249

[6] CVE-2026-90439 — NGINX HTTP/3 (`ngx_http_v3_module`) heap buffer overflow (background). NVD. https://nvd.nist.gov/vuln/detail/CVE-2026-90439

## 부록: AI-대-본인 판단 공개
