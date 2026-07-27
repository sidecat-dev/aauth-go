# AAuth Go implementation guidance

## Purpose

This repository is an independent Go implementation of AAuth built by the
Sidecat maintainers. Its immediate consumer is Sidecat. It is not an upstream
AAuth repository and carries no commitment to publish or contribute it.

## Boundaries

- Keep every protocol package usable without Sidecat. Do not import Sidecat
  code, types, stores, policy, or configuration.
- Put deployment policy behind explicit interfaces: key resolution, clocks,
  randomness, replay custody, mission decisions, authorization decisions, and
  protected operations.
- Treat the locally pinned AAuth editor drafts as the protocol source. Existing
  Sidecat Go and BEAM implementations are interoperability peers and sources of
  implementation experience, not code to transplant.
- Preserve exact wire bytes where the protocol binds them. In particular,
  mission `s256` is over the exact approved response bytes.
- Reject incomplete authorization. JWT verification, request proof,
  audience/issuer/agent/key binding, mission binding, scope, time, and replay
  are separate checks.
- Public names and fixtures must be generic and suitable for an independent
  open-source implementation.

## Working method

- Add a failing externally visible behavior test before production code.
- Build complete paths through real HTTP handlers and cryptographic
  verification. Unit tests support those paths; they do not replace them.
- Record draft ambiguity or interoperability findings in the existing AAuth
  feedback custody only after executable evidence exists.
- Do not add upstream remotes, namespaces, publication metadata, or submissions
  without an explicit operator decision.

## Completion claims

Name the implemented draft/profile and exclusions precisely. Do not call the
implementation complete while a required role, protocol path, refusal, or
declared conformance case is missing.
