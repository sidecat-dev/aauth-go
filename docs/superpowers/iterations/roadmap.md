# M4 evidence roadmap

This roadmap orders implementation evidence for the already accepted AAuth
M4 conditional per-call vertical. Sidecat remains the authority for milestone
and work state. This document neither revises the accepted M1-M8 roadmap nor
schedules M5 Events work.

**Reconciliation (2026-08-02):** The initial three-step evidence draft listed
STORY-0001 through STORY-0004 in both ITER-0000 and ITER-0001. The refusal and
exact-binding matrix is required to complete those same acceptance criteria,
so it is now part of the walking skeleton. ITER-0001 is retained as a visible
superseded plan node; no new product story or accepted milestone work moved.

## Walking skeleton (ITER-0000)

**Intent:** Prove the real agent → resource → PS → AS → resource HTTP journey
from a conditional initial token through a non-executing proposal challenge to
one parameter-bound protected operation.
**Stories:** STORY-0001 through STORY-0004
**Journey:** JOURNEY-0001
**Status:** done
**Impacted scenarios:** JOURNEY-0001, SCENARIO-0001 through SCENARIO-0006

## ITER-0001 — Refusal and exact-binding matrix (superseded)

**Stories:** none; folded into ITER-0000
**Rationale:** These are proof obligations of STORY-0001 through STORY-0004,
not a second delivery of those stories. Keeping them inside the complete
walking skeleton avoids a shallow happy-path milestone.
**Status:** superseded by ITER-0000
**Impacted scenarios:** none independently

## ITER-0002 — Restart, replay, and regression qualification

**Stories:** STORY-0005
**Rationale:** Prove that exact proposal custody is useful after resource
reconstruction and that repeated or substituted proof does not execute work.
Then rerun all maintained-source and M3 sentinel evidence.
**Status:** done
**Impacted scenarios:** SCENARIO-0007, SCENARIO-0008

## Excluded from M4 claims

- PS wire retrieval of R3 documents or proposals, because the pinned draft's
  PS-fetch requirement conflicts with its AS-only endpoint rule.
- Scope-free R3, multi-definition composition, every-vocabulary live adapter,
  deferred R3 issuance, multi-process document-store writers, and permanent
  historical document service.
- Events, Bootstrap, release transition, and any Sidecat-specific integration.
