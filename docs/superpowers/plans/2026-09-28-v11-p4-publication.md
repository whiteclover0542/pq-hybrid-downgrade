# v1.1 P4 Publication and Reproduction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish the validated v1.1 P2/P3 observations as the primary paper and a self-contained, safely reproducible v1.1 package.

**Architecture:** Keep final P2 raw data immutable and use it as the sole numerical source. Add read-only v1.1 reporting and fresh-output execution support to the existing fault-injector, then package only `raw/v1.1/` and its supporting documentation. Rewrite the paper around P3's scoped conclusion; v1.0 remains a short motivation/control, not a parallel result set.

**Tech Stack:** Markdown, Python 3 standard library, pytest, zipfile, existing `tools/faultinject` modules.

**Spec:** `docs/superpowers/specs/2026-09-28-v11-p4-publication-design.md`.

## 한국어 검토 요약

[확실] 이 계획은 네 작업으로 진행합니다. 첫째, `--v11` 실행에 새 출력 폴더를 지정하는 옵션과 원시 데이터를 바꾸지 않는 v1.1 집계·분석 명령을 추가합니다. 따라서 보존된 최종 `raw/v1.1/` 90건을 덮어쓰지 않습니다.

[확실] 둘째, 재현 ZIP을 v1.1 최종 데이터·PCAP·클라이언트 로그·캡처 로그·프록시 로그·분석 문서만 포함하도록 바꾸고, 진단·부분 실행 데이터가 들어가면 검증이 실패하게 합니다.

[확실] 셋째, 논문과 재현 안내서를 v1.1 중심으로 다시 씁니다. v1.0은 왜 v1.1이 필요했는지를 설명하는 짧은 배경으로만 남깁니다. 결론은 “시험한 조건에서 관측된 현상”에 한정하고, CVE 재현·RFC 위반·실제 취약점이라고 주장하지 않습니다.

[확실] 넷째, 전체 테스트, 원시 90건 재집계, ZIP 검증, 논문 표 대조를 끝낸 후에만 P4 완료 상태·요약을 기록하고 커밋·푸시합니다.

## Global Constraints

- Use only `docs/research/baselines/raw/v1.1/` for v1.1 numerical claims; exclude every `v1.1-pre-*`, `v1.1-diagnose*`, and preflight directory.
- Do not rerun an experiment into the preserved `raw/v1.1/` directory or modify its 90 JSON records and artifacts.
- Do not claim CVE reproduction, universal behavior, RFC non-conformance, practical exploitability, or a new vulnerability.
- Keep OpenSSH on-path-strip as a failed structural control, never as a successful TLS-equivalent downgrade.
- The final ZIP must contain no excluded diagnostic/partial v1.1 directories.

## Review Focus

- `--output-dir` must affect v1.1 runs only and must not silently alter legacy phase-3/phase-4 output locations.
- v1.1 reporting must be read-only; aggregation and analysis cannot create or overwrite files under the final dataset.
- ZIP verification must reject packages missing any required v1.1 artifact class, even when 90 JSON files exist.
- Paper totals, negotiated groups, HRR counts, and audit-flag counts must match P3 exactly.
- The paper must distinguish the operational meaning of “silent” from RFC/security conclusions.

---

### Task 1: Safe v1.1 execution and read-only reporting interfaces

**Files:**
- Modify: `tools/faultinject/run.py`
- Modify: `tools/faultinject/aggregate.py`
- Modify: `tools/faultinject/analyze.py`
- Modify: `tools/faultinject/tests/test_v11_runner.py`
- Modify: `tools/faultinject/tests/test_v11_reporting.py`

**Interfaces:**
- Consumes: existing `run_v11(repetitions: int, output_dir: Path | None = None)`, `aggregate_v11(run_dir)`, and `comparison_v11(run_dir)`.
- Produces: `python -m faultinject.run --v11 N --output-dir PATH`, plus read-only `--v11 [--run-dir PATH]` modes for aggregate and analysis.

- [ ] **Step 1: Add failing CLI-routing tests.**

  In `test_v11_runner.py`, mock `preflight` and `run_v11`; call `run.main(["--v11", "2", "--output-dir", str(tmp_path)])`; assert `run_v11(2, output_dir=tmp_path)` receives the supplied path. Add one test that `--output-dir` without `--v11` returns an argument error and does not call a runner.

- [ ] **Step 2: Add failing read-only reporting tests.**

  In `test_v11_reporting.py`, use v1.1 fixture records and assert `aggregate.main(["--v11", "--run-dir", str(tmp_path)])` and `analyze.main(["--v11", "--run-dir", str(tmp_path)])` return zero, print condition-axis output, and leave the directory file list unchanged.

- [ ] **Step 3: Implement the v1.1 CLI options.**

  In `run.py`, add `--output-dir` as `Path`; reject it unless `--v11` is selected; pass it to `run_v11`. In `aggregate.py` and `analyze.py`, add `--v11` and optional `--run-dir`; default to `raw/v1.1/`, print the existing v1.1 count/analysis structures, and do not call either manifest writer.

- [ ] **Step 4: Verify the focused tests and preserve legacy behavior.**

  Run from `tools/`: `python -m pytest faultinject/tests/test_v11_runner.py faultinject/tests/test_v11_reporting.py -q`.

- [ ] **Step 5: Commit the safe v1.1 interfaces.**

  ```bash
  git add tools/faultinject/run.py tools/faultinject/aggregate.py tools/faultinject/analyze.py tools/faultinject/tests/test_v11_runner.py tools/faultinject/tests/test_v11_reporting.py
  git commit -m "feat: add safe v1.1 execution and reporting CLI"
  ```

### Task 2: Build and verify a v1.1-only reproduction ZIP

**Files:**
- Modify: `tools/make_repro_package.py`
- Modify: `tools/faultinject/tests/test_repro_package.py`

**Interfaces:**
- Consumes: final `docs/research/baselines/raw/v1.1/`, `tools/faultinject/*.py`, and P2/P3 source documents.
- Produces: `build_zip(out_path: Path) -> Path` and `verify_zip(zip_path: Path) -> tuple[bool, list[str]]` for a v1.1 package.

- [ ] **Step 1: Write failing package-content tests.**

  Update `test_repro_package.py` to require 90 v1.1 JSON records, 90 PCAPs, 90 client logs, 90 capture logs, 30 proxy logs, `docs/PAPER.md`, the v1.1 design, P2 summary, P3 analysis, and `REPRODUCTION.md`. Assert that no member path contains `v1.1-diagnose`, `v1.1-pre-`, or `v1.1-preflight`.

- [ ] **Step 2: Implement v1.1 packaging and verifier requirements.**

  Replace phase-4-only constants with v1.1 paths. Bundle the final v1.1 directory only, all fault-injector Python source, `PAPER.md`, `REPRODUCTION.md`, the v1.1 design, and P2/P3 documents. Make `verify_zip` count every required artifact class and report each missing class explicitly.

- [ ] **Step 3: Run package tests and create a candidate ZIP.**

  Run from `tools/`: `python -m pytest faultinject/tests/test_repro_package.py -q`; then run `python make_repro_package.py --out ../dist/pq-hybrid-downgrade-v11-repro.zip` and verify it returns `(True, [])`.

- [ ] **Step 4: Commit the package builder and generated v1.1 ZIP.**

  ```bash
  git add tools/make_repro_package.py tools/faultinject/tests/test_repro_package.py dist/pq-hybrid-downgrade-v11-repro.zip
  git commit -m "feat: package validated v1.1 reproduction artifacts"
  ```

### Task 3: Rewrite paper and reproduction guidance around v1.1

**Files:**
- Modify: `docs/PAPER.md`
- Modify: `docs/research/REPRODUCTION.md`

**Interfaces:**
- Consumes: P3 table and interpretation in `docs/research/v1.1-p3-analysis.md`, P2 execution evidence, Task 1 CLI, and Task 2 package layout.
- Produces: v1.1-primary paper and a guide that preserves final data while enabling independent inspection/re-execution in a fresh output directory.

- [ ] **Step 1: Rewrite the paper’s abstract, introduction, and methods.**

  Make v1.1 the research focus. Keep one concise v1.0 design-evolution paragraph. Describe the nine v1.1 combinations, 10 repetitions each, the final-data boundary, the `advertised_hybrid`, HRR, audit-flag, negotiated-group, and verification measurements.

- [ ] **Step 2: Replace the result and discussion sections with the P3 evidence table.**

  Copy all nine rows and their exact values from P3. Explain condition C, the verified TLS on-path control, audit visibility, and the OpenSSH structural control. State the P3 scope-limited conclusion and limitations verbatim in substance.

- [ ] **Step 3: Retain only valid contextual references and disclosure.**

  Preserve the AI-versus-human disclosure. Keep references only when they are actually used for background; do not let a reference imply normative RFC analysis not performed in P4.

- [ ] **Step 4: Rewrite the reproduction guide.**

  Document the final data boundary and excluded directories; provide read-only `aggregate --v11` and `analyze --v11` commands; provide the fresh-output `run --v11 10 --output-dir PATH` command and an explicit warning never to use the default output path against preserved final data; document ZIP verification.

- [ ] **Step 5: Validate documentation claims.**

  Recompute the raw 90-record summary, compare it with every paper table row, and scan the paper/guide for `TBD`, `TODO`, and `placeholder`. Confirm no prohibited conclusion string appears.

- [ ] **Step 6: Commit the v1.1-primary publication text.**

  ```bash
  git add docs/PAPER.md docs/research/REPRODUCTION.md
  git commit -m "docs: make v1.1 evidence the primary paper result"
  ```

### Task 4: Final P4 verification and milestone record

**Files:**
- Create: `.planning/phases/07-v11-tooling/07-04-SUMMARY.md`
- Modify: `.planning/STATE.md`
- Modify: `.planning/ROADMAP.md`

**Interfaces:**
- Consumes: Tasks 1–3 artifacts and their verification output.
- Produces: a completed v1.1 milestone record with P4 evidence links.

- [ ] **Step 1: Run the final verification suite.**

  Run from `tools/`: `python -m pytest -q`; rebuild the v1.1 ZIP; run `verify_zip`; run the read-only v1.1 aggregate and analysis; and independently verify 90 records, nine complete repetition groups, artifact counts, and no excluded paths in the ZIP.

- [ ] **Step 2: Write the P4 summary.**

  Record the final verification outputs, the precise paper conclusion, scope limits, ZIP contents, and that no new experiment was run or final P2 data altered.

- [ ] **Step 3: Mark v1.1 complete in planning state.**

  Set v1.1 to 4/4 phases and 100%; retain P1–P3 history; link the P4 summary; and state that the published conclusion remains scoped and not a CVE/RFC finding.

- [ ] **Step 4: Commit and push P4.**

  ```bash
  git add .planning/STATE.md .planning/ROADMAP.md .planning/phases/07-v11-tooling/07-04-SUMMARY.md
  git commit -m "docs(07-04): publish validated v1.1 study"
  git push origin v1.1-hrr-downgrade
  ```

## Self-Review

[확실] Spec coverage: Task 1 provides fresh output and read-only reporting; Task 2 limits ZIP membership and verifies it; Task 3 converts the publication and guide; Task 4 records completion only after validation.

[확실] The plan has no task that alters final raw data, runs a new experiment, or makes a normative vulnerability claim.

[확실] Review-focus coverage: Task 1 tests output routing and read-only modes; Task 2 tests artifact-class completeness and excluded paths; Task 3 verifies paper-table values and claim limits; Task 4 rechecks all release artifacts.
