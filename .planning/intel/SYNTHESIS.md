# Ingest Synthesis Summary

Entry point for gsd-roadmapper. Mode: new. Generated 2026-09-22.

## Doc counts by type

- PRD: 1 (PROPOSAL.md)
- DOC: 8 (PROGRESS.md + phase-0..6 plans)
- ADR: 0
- SPEC: 0
- Total: 9

## Decisions locked

- 0 (no ADRs ingested). See decisions.md.

## Requirements extracted

- 8, from PROPOSAL.md. See requirements.md.
  - REQ-hypothesis-lock
  - REQ-prior-work-verification
  - REQ-testbed-three-implementations
  - REQ-fault-injector
  - REQ-repeated-execution
  - REQ-observation-metrics
  - REQ-cross-implementation-analysis
  - REQ-reproduction-package

## Constraints

- 0 canonical constraints (no SPECs). See constraints.md.
- Note: PROPOSAL.md holds SPEC-adjacent design detail (system diagram, testbed target table, fault-injection methods, observation-metric table), captured as requirements + context rather than binding constraints.

## Context topics

- 9, from the 8 DOC sources + proposal background. See context.md.
  - Project state & phase roadmap
  - Phase 0 planning through Phase 6 writeup (7 per-phase topics)
  - Motivating CVE observations (background)

## Cross-reference graph

- Directed graph from cross_refs: PROGRESS.md -> {plans/, phase-0..6, PROPOSAL.md}; phase-0-planning.md -> PROPOSAL.md.
- Cycle detection (DFS three-color): no cycles. Max depth 2 (well under the 50 cap).

## Conflicts

- Blockers: 0
- Competing variants: 0
- Auto-resolved: 0
- Detail: D:\sr\pq-hybrid-downgrade\.planning\INGEST-CONFLICTS.md

## Per-type intel files

- Decisions: D:\sr\pq-hybrid-downgrade\.planning\intel\decisions.md
- Requirements: D:\sr\pq-hybrid-downgrade\.planning\intel\requirements.md
- Constraints: D:\sr\pq-hybrid-downgrade\.planning\intel\constraints.md
- Context: D:\sr\pq-hybrid-downgrade\.planning\intel\context.md

## Routing status

READY — no blockers, no variants. Safe to route to gsd-roadmapper.
