// Package r3 implements the vocabulary-neutral values and proof rules of
// AAuth Rich Resource Requests.
//
// Operation-bearing input is parsed through an explicit Registry. Standard
// operation grammars are in r3/vocab; applications may register a smaller
// allowlist or a third-party vocabulary. Documents and proposals retain their
// vocabulary semantics, while references bind the exact bytes independently
// of parsing or reserialization.
//
// This package does not fetch definitions, decide policy, retain artifacts,
// execute calls, or write issuance audits. The participating role packages
// own those effects.
package r3
