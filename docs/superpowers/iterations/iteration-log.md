# M4 iteration log

## ITER-0000 — Conditional per-call walking skeleton

**Completed:** 2026-08-02

**Stories delivered:** STORY-0001, STORY-0002, STORY-0003, STORY-0004

**Tasks executed:** Added disjoint conditional grants, strict exact proposal
construction and custody, AS-only fetch and exact direct approval, durable
issuance recovery plus independent audit-before-release, exact-call retry
mapping, and refusal coverage at each authority boundary.

**Scenarios:** Automated JOURNEY-0001 and SCENARIO-0001 through SCENARIO-0006.
The integrated journey and complete Go suite pass. The M3 direct-grant journey
also passes as the carried sentinel. The initial M4 edits predated creation of
this local iteration artifact, so no separate artifactized pre-edit sentinel
output is claimed.

**Summary:** One real signed HTTP and cryptographic four-party journey now
moves from a conditional class grant to a non-executing exact proposal, durable
approval, and one matching protected operation. Malformed, partial, recursive,
overgranted, uncustodied, and parameter-mutated paths fail closed.

## ITER-0002 — Restart, replay, and regression qualification

**Completed:** 2026-08-02

**Stories delivered:** STORY-0005

**Tasks executed:** Added restart-safe exact proposal state, proposal metadata
capacity accounting, exact-token recovery across access-server reconstruction,
durable consume-before-effect admission, proof replay refusal, and missing,
expired, corrupt, substituted, concurrent, and fresh-proof reuse evidence.

**Scenarios:** Automated SCENARIO-0007 and SCENARIO-0008 and reran all sentinel
scenarios. The complete suite and race suite pass; M3 direct grant remains
green.

**Summary:** Resource and access-server process replacement preserve exact
proposal enforcement without minting another usable token. One fresh matching
request may cross the durable admission boundary; later proof or token reuse is
refused. This is explicitly at-most-once admission, not exactly-once external
consequence.
