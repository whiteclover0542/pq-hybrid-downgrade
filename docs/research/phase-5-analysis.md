# 하이브리드-PQ 다운그레이드 저항성 분석 (Phase 5)

## 가설

협상 로직 결함(supported_groups 조작 및 결합자 바인딩 위반)이 하이브리드-PQ 그룹을 고전 전용으로 다운그레이드시키는 것은 특정 라이브러리의 우연한 버그가 아니라 독립 코드베이스 전반의 패턴이다.

## 연구 질문

3개 독립 구현체(OpenSSL, BoringSSL, OpenSSH)에서 동일한 두 가지 협상 로직 결함(group-list 조작, binding 결합자 위반)이 항상 동일한 결과(group-list는 다운그레이드, binding은 거부)를 낳는가? 이는 결함이 "버그"가 아니라 설계 예상(Bhargavan et al., Transcript-Bound Combiners 2026-09)임을 시사한다.

## 증명된-안전 대 배포된-안전

하이브리드 컴바이너 다운그레이드 저항성은 Bhargavan et al.의 공식 증명(Transcript-Bound Combiners, 2026-09)에 의해 정의된 설계(proven-safe)이다. 본 연구는 그 설계의 실제 배포 구현들(as-deployed safe) 거동을 현지 루프백 테스트를 통해 시험한다. 증명과 배포 사이의 간극을 측정하는 것이 목표다.

## 구현체별 비교

| implementation | fault_type | verified/n | success | failure | downgrade | negotiated group(s) |
|---|---|---|---|---|---|---|
| boringssl | binding | 10/10 | 0 | 10 | 0 | - |
| boringssl | group-list | 10/10 | 10 | 0 | 10 | X25519 |
| openssh | binding | 10/10 | 0 | 10 | 0 | sntrup761x25519-sha512@openssh.com |
| openssh | group-list | 10/10 | 10 | 0 | 10 | curve25519-sha256 |
| openssl | binding | 10/10 | 0 | 10 | 0 | - |
| openssl | group-list | 10/10 | 10 | 0 | 10 | X25519 |
