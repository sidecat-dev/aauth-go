# Maintaining aauth-go against the moving AAuth drafts

Three maintained processes: refreshing the retained AAuth documents,
managing the feedback journal to the AAuth authors, and updating this
implementation.

## 1. Updating the retained AAuth documents (`~/data/aauth-drafts/`)

The protocol source is the author's editor repositories, not IETF-hosted
renders: `https://github.com/dickhardt/AAuth` and
`https://github.com/dickhardt/signature-key`.

1. Move the current snapshot to `~/data/crawls/aauth-<date>/` so prior
   digests keep a resolvable home.
2. Fetch at one pinned commit per repository. Retain the editor-source
   Markdown byte-exact — those bytes are the digest referents. Rendered
   publication snapshots (HTML/text) may be retained alongside, but a
   render is never a stronger source than its pinned Markdown.
3. Update `PROVENANCE.md` in the same change: one row per local file
   naming the upstream identity (repository, commit, draft name), the
   SHA-256 of the exact retained bytes, and whether the file is editor
   source or a rendered snapshot.
4. Never silently relabel retained bytes. Precedent: the signature-key
   tree tagged `84f2d831` as revision `-07` while its generated
   artifacts self-identify as `-06`; the mismatch is recorded, the bytes
   are kept as fetched.

## 2. Implementation interpretations and feedback

`INTERPRETATIONS.md` is the single public register for choices that affect
observable protocol behavior. `implementation-journal.md` retains the
executable implementation findings that support those choices.
`SPEC-FEEDBACK.md` tracks evidence-backed questions prepared for the AAuth
authors and their upstream dispositions. Read all three before classifying a
finding as new.

- A finding enters the journal only after executable evidence exists: a
  failing test, a wire capture, or a journey demonstrating the ambiguity.
- Each interpretation records the exact source revision and section, chosen
  behavior, plausible alternatives, reason, executable evidence,
  current-product effect, and later disposition.
- Each upstream feedback item starts from executable evidence, asks one neutral
  question, links its upstream thread, and records the authors' disposition.
- Feedback is submitted to the authors as Joshua Gay, never as "we" and
  never as an agent.

## 3. Updating aauth-go

This unreleased implementation is clean-current only. Replace or remove an
obsolete schema, wire shape, package contract, or behavior in the same change;
do not add or retain migration readers, compatibility modes, deprecated
aliases, fallbacks, or dual paths. An obsolete form may remain only as raw
negative test input proving that the current implementation rejects it.

1. **Re-pin.** Copy the new exact source bytes into
   `internal/sourcecoverage/sources/` and update the coverage manifest's
   revision strings and digests. The profile-naming test forces the
   profile claim to move with the pins; every digest must resolve from a
   fresh clone.
2. **Regenerate.** `go run ./internal/sourcecoverage/cmd/generate`
   (zero-flag; it defaults to the retained repository sources) and
   verify with `go run ./cmd/aauth-reference verify coverage`.
3. **Implement** per the working method in `AGENTS.md`: a failing
   externally visible behavior test first, then complete paths through
   real HTTP handlers and cryptographic verification. Dependency order
   follows the dependency analysis: Signature-Key wire format first,
   then person-token topology, then missions and chaining, then a separately
   reviewed current R3 implementation. Each phase regenerates its current Go fixtures and
   journey evidence. Historical cross-language fixtures remain raw negative
   vectors only; they do not earn an alternate runtime path.
4. **Close** with the full suite, race suite, coverage verification, `go vet`,
   and a clean diff check before handing the exact diff to the authorized
   integration path.
