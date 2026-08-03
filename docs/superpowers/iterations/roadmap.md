# AAuth evidence roadmap

This roadmap orders repository evidence for the accepted AAuth M4 and M5
verticals. Sidecat remains the authority for milestone and work state. M4 and
M5 are closed. The completed M5 Events successor includes its accepted
Signature-Key self-jwt dependency; this does not revise the dependency-ordered
M1-M8 roadmap.

**Reconciliation (2026-08-02):** The initial three-step evidence draft listed
STORY-0001 through STORY-0004 in both ITER-0000 and ITER-0001. The refusal and
exact-binding matrix is required to complete those same acceptance criteria,
so it is now part of the walking skeleton. ITER-0001 is retained as a visible
superseded plan node; no new product story or accepted milestone work moved.

## Walking skeleton (ITER-0000)

**Intent:** Prove the real agent → resource → PS → AS → resource HTTP journey
from a conditional initial token through a non-executing proposal challenge to
one parameter-bound protected operation.
**Design rationale:** This is the historical M4 walking skeleton and remains
the first complete journey in the maintained evidence corpus.
**Stories committed:** STORY-0001, STORY-0002, STORY-0003, STORY-0004
**Journey scenario:** JOURNEY-0001
**Status:** done
**Impacted scenarios:** JOURNEY-0001, SCENARIO-0001 through SCENARIO-0006

## Iteration list

### ITER-0001 — Refusal and exact-binding matrix (superseded)

**Stories:** none; folded into ITER-0000
**Rationale:** These are proof obligations of STORY-0001 through STORY-0004,
not a second delivery of those stories. Keeping them inside the complete
walking skeleton avoids a shallow happy-path milestone.
**Status:** superseded by ITER-0000
**Impacted scenarios:** none independently

### ITER-0002 — Restart, replay, and regression qualification

**Stories:** STORY-0005
**Rationale:** Prove that exact proposal custody is useful after resource
reconstruction and that repeated or substituted proof does not execute work.
Then rerun all maintained-source and M3 sentinel evidence.
**Status:** done
**Impacted scenarios:** SCENARIO-0007, SCENARIO-0008

### ITER-0003 — Public-subscription event lifecycle

**Intent:** Prove one complete AP-issued public subscription through resource
registration, delivery-time endpoint resolution, one durable payload-free
event, and one independently verified agent action after reconstruction.
**Design rationale:** STORY-0006 through STORY-0015 close the runtime journey;
STORY-0016 is the separate milestone honesty/closure gate, and STORY-0017
qualifies bounded replaceable host storage. Portable self-jwt is
application-neutral, and AP authority/inbox, resource subscription, adapter
continuation, and agent context/dedup stay distinct deployment-owned
interfaces. Bounded single-writer file implementations qualify replacement
and recovery behavior without becoming an enterprise storage ceiling.
**Stories:** STORY-0006, STORY-0007, STORY-0008, STORY-0009, STORY-0010,
STORY-0011, STORY-0012, STORY-0013, STORY-0014, STORY-0015, STORY-0016,
STORY-0017
**Journey scenario:** JOURNEY-0002
**Status:** done
**Completed:** 2026-08-03
**Impacted scenarios:** JOURNEY-0002, SCENARIO-0009 through SCENARIO-0024
**Harness-first task:** Extend the existing real-HTTP logical gateway with
separate AP, resource, adapter, and agent reconstruction seams. The first RED
must express the complete journey—including lost-response retry and
crash-after-agent-admission continuation—before production code is added.
**Look-ahead check:** M6 reuses the admitted operation and versioned
deployment-store interfaces. It adds protected ticket authority, AsyncAPI
discovery/schema/payload proof, any clarified multi-event replay identity, and
may extend the non-normative deployment adapter; none is simulated or frozen
into protocol wire here.

## Closed M4 boundaries

- PS wire retrieval of R3 documents or proposals, because the pinned draft's
  PS-fetch requirement conflicts with its AS-only endpoint rule.
- Scope-free R3, multi-definition composition, every-vocabulary live adapter,
  deferred R3 issuance, multi-process document-store writers, and permanent
  historical document service.
- Bootstrap, release transition, and any Sidecat-specific integration.

## Excluded from M5 claims

- Protected subscription tickets and AsyncAPI discovery/schema/payload support
  (M6). AP-to-agent transport remains non-normative; M6 may extend the
  deployment adapter but does not standardize it without a separate accepted
  specification decision.
- Multiple independently deduplicable events under one `eid`, pending source
  clarification of the event identity/replay model.
- Universal Signature-Key algorithm support, a built-in network access policy,
  or a JWT acquisition protocol.
- Bootstrap, release transition, and any Sidecat-specific integration.
