# Contributing

Thank you for helping improve AAuth Go.

## Before you change protocol behavior

Read `README.md`, `ARCHITECTURE.md`, and `SPECIFICATIONS.md`. Check
`INTERPRETATIONS.md` and `SPEC-FEEDBACK.md` before choosing behavior where
the source text is ambiguous.

Keep changes grounded in an exact source document, revision, and section.
Implementation convenience is not a protocol requirement.

## Make a focused change

1. Add a failing test for the observable behavior.
2. Implement the smallest complete change.
3. Add refusal cases for relevant identity, audience, proof-key, lifetime,
   replay, and context bindings.
4. Keep Core and companion package dependencies in the direction documented in
   `ARCHITECTURE.md`.
5. Update public documentation only when the supported behavior changes.

Use synthetic keys and identities in tests. Never add real tokens, credentials,
private keys, or personal data.

## Verify the change

Run a focused test first. Before opening a pull request, run:

```sh
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
git diff --check
```

Run `gofmt` on every changed Go file.

## Describe the change

In the pull request, include:

- the source document, revision, and section;
- the observable behavior that changed;
- the tests that demonstrate it;
- any interpretation the source does not require;
- any behavior that remains unimplemented or unverified.

Keep specification feedback neutral and reproducible. A useful report states
the exact text, the observable interoperability or security effect, and the
smallest test or wire example that demonstrates it.
