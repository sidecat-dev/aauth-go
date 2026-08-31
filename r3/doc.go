// Package r3 implements the vocabulary-neutral values and proof rules of
// AAuth Rich Resource Requests.
//
// Operation-bearing input is parsed through an explicit Registry. Standard
// operation grammars are in r3/vocab; applications may register a smaller
// allowlist or a third-party vocabulary. Documents and proposals retain their
// vocabulary semantics, while references bind the exact bytes independently
// of parsing or reserialization.
//
// DefinitionParser is the separate native-definition boundary. One atomic
// parse produces a copied AuthoritativeSnapshot containing a semantic
// operation set, sparse advisory hints, and a receipt over the adapter's named
// digest input. The snapshot retains no source bytes, parser AST, transport,
// policy, or lifecycle state.
//
// This package does not fetch definitions, decide policy, retain artifacts,
// execute calls, or write issuance audits. The participating role packages
// own those effects.
package r3
