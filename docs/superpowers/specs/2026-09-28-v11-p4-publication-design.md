# v1.1 P4 Publication and Reproduction Design

## Intent

[확실] P4 will turn the validated v1.1 P2/P3 work into the primary paper and reproduction deliverable. The paper will answer the v1.1 research question: under the tested configuration, does a hybrid-advertising TLS client that sends a classical key share first complete a classical handshake without HRR and without an automatic audit flag?

[확실] The final paper must preserve the evidence boundary: final data is only `docs/research/baselines/raw/v1.1/` (90 JSON records and their artifacts). Partial, preflight, and diagnostic v1.1 directories are excluded. No text will claim a CVE reproduction, universal implementation behavior, RFC non-conformance, or practical exploitability.

## Scope and narrative

[확실] `docs/PAPER.md` will be rewritten around v1.1. Its abstract, methods, result table, discussion, conclusion, and limitations will cite the 90-record P2/P3 observations: 10/10 successful classical `X25519` negotiations for each tested TLS implementation in `silent-downgrade`; no recorded HRR; no automatic downgrade flag; and verified on-path failures.

[확실] v1.0 will not remain a parallel result series. It will appear only as a short design-evolution paragraph: its client-side classical-only group-list setup made the outcome visible and did not test the v1.1 advertised-hybrid/key-share-order question. Its successful packet-modification rejection remains contextual motivation for the v1.1 on-path control, not a coequal result table.

[확실] OpenSSH will be reported as a structural control. Its on-path-strip result is a failed connection with a parsed hybrid KEX, not a successful downgrade and not a third TLS `key_share` data point.

## Publication structure

[확실] The paper will contain: title/metadata; abstract; introduction and v1.0-to-v1.1 design evolution; method; final-data results table; constrained discussion; limitations; references; and the existing AI-versus-human disclosure.

[확실] The result table will retain all nine implementation/condition combinations, with total, success, failure, verified, `hrr_present`, `downgrade_flagged`, `is_hybrid`, and recorded negotiated group/KEX. The table and prose must agree with `docs/research/v1.1-p3-analysis.md`.

[확실] The conclusion will use the P3 wording: under the tested group order and audit definition, the two TLS implementations completed a classical handshake after hybrid advertisement without a recorded HRR or automatic downgrade flag. Verified on-path alteration failed in this testbed.

[불확실] The paper will explicitly state that whether this behavior is RFC-conformant, exploitable, or a vulnerability needs normative and broader-environment evidence beyond this study.

## Reproduction package

[확실] `tools/make_repro_package.py` will package the final `raw/v1.1/` records and artifacts, `tools/faultinject` source, the v1.1 design/P2/P3/reproduction documents, and the paper. The package verifier will require exactly the v1.1 evidence set needed for review: at least 90 JSON records, 90 PCAPs, 90 client logs, 90 capture logs, 30 on-path proxy logs, and core analysis/reproduction documents.

[확실] `docs/research/REPRODUCTION.md` will be rewritten for v1.1. It will tell reviewers how to inspect the preserved final dataset and regenerate the aggregate rather than instructing them to overwrite it. It will distinguish final data from excluded diagnostic/partial directories.

[확실] The v1.1 CLI will gain an explicit output-directory option so a new experiment can write to a fresh directory. The guide will state that `--v11 10` with its legacy default path must not be used against the preserved final dataset.

## Validation and completion

[확실] Tests will cover the new CLI output-directory routing and the v1.1 reproduction ZIP requirements. The tool suite will run from `tools/`.

[확실] Release validation will recompute final-data counts, build and verify the ZIP, confirm P4 did not package excluded diagnostic/partial v1.1 data, check that paper claims match the P3 table, and scan final documents for placeholders.

[확실] Only after those checks pass will P4 update `STATE.md`, `ROADMAP.md`, its P4 summary, commit, and push. The prior P1–P3 records remain intact.

## Out of scope

[확실] P4 will not run another 90-record experiment, alter the preserved final P2 dataset, delete diagnostic data, perform a normative RFC analysis, or assign a vulnerability/CVE identity.
