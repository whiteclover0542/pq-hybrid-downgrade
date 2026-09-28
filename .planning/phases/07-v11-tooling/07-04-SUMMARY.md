---
phase: 07-v11-tooling
plan: 04
status: complete
completed: 2026-09-28
---

# v1.1 P4 Publication and Reproduction Summary

## Published deliverables

[확실] `docs/PAPER.md` now makes v1.1 the primary result. It reports only the final `docs/research/baselines/raw/v1.1/` dataset and preserves the exact nine-row, ten-repetition result table.

[확실] `docs/research/REPRODUCTION.md` now distinguishes read-only review from a fresh experiment. It requires `--output-dir` for a new v1.1 run and explicitly protects the preserved final dataset from overwrite or proxy-log accumulation.

[확실] `dist/pq-hybrid-downgrade-v11-repro.zip` was rebuilt after the document update. It contains the final v1.1 raw data and artifacts, `tools/faultinject` source, the paper, the v1.1 design, P2 summary, P3 analysis, and the reproduction guide. It excludes diagnostic, preflight, and partial-run paths.

## Final verification

[확실] `python -m pytest -q` from `tools/` completed with `69 passed, 1 skipped`. The one warning was a pytest cache write permission warning and did not fail a test.

[확실] Read-only `faultinject.aggregate --v11` and `faultinject.analyze --v11` report nine rows, each with `total=10` and `verified=10`; every row has HRR count 0 and automatic downgrade-flag count 0.

[확실] An independent raw-file check found exactly 90 JSON records, nine complete r01–r10 repetition groups, 90 verified manipulations, 90 non-empty PCAPs, 90 non-empty client logs, 90 non-empty capture logs, 30 non-empty proxy logs, and no missing referenced artifact.

[확실] `verify_zip` returned `(True, [])`. A separate ZIP membership check found 500 entries and no `v1.1-diagnose`, `v1.1-pre-`, or `v1.1-preflight` paths.

## Publication conclusion and boundary

[확실] In the tested TLS configurations, OpenSSL and BoringSSL recorded a successful classical `X25519` negotiation after hybrid advertisement and a classical-first `key_share`, with no recorded HRR or automatic downgrade flag. The verified TLS on-path stripping condition instead failed in every repetition.

[확실] OpenSSH is retained as a structural control: its on-path condition failed and is not interpreted as a successful TLS downgrade.

[확실] Post-publication interpretation supplement: OpenSSL v1.1 used the explicit single tuple `X25519MLKEM768:X25519`. Its documented group-list algorithm accepts an already received `X25519` key share from that tuple, so the v1.1 OpenSSL condition is not evidence of the `DEFAULT` tuple-loss path in CVE-2026-2673. The final raw data and artifact inventory remain unchanged.

[불확실] The publication does not determine RFC non-conformance, CVE equivalence, practical exploitability, or behavior outside the fixed implementations, group order, loopback environment, and audit definition.

## Data integrity

[확실] P4 ran no new handshake experiment. The final `raw/v1.1/` directory was not modified by any P4 commit; P4 used only read-only reporting and package construction.
