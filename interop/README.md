# Retained interoperability fixtures

The Elixir-attributed fixtures in this directory have not been regenerated or
reciprocally verified during the current maintenance run. Their embedded
provenance says they came from the earlier `sidecat-beam` prototype and their
compact JWS headers use draft-06's polymorphic `EdDSA` identifier. The active
draft-08 Go verifier deliberately rejects those exact bytes with
`unsupported_algorithm`. Treat them as immutable historical comparator
material, not current interoperability vectors.

`elixir-agent-request.json` records an Elixir-minted
`aa-agent+jwt`, an Elixir-serialized `AAuth-Mission` reference, and an
Elixir-created RFC 9421 request signature using the JWT Signature-Key scheme.
The Go test reconstructs the HTTP request from those exact wire values and
proves the Phase-1 compatibility boundary: the prohibited token algorithm is
rejected before draft-09 claims or its request signature can be accepted.

The fixture records the exact `sidecat-beam` commit that generated it. To
regenerate from a checked-out copy at that commit:

```sh
cd /absolute/path/to/sidecat-beam
mix run /absolute/path/to/aauth-go/interop/generate_elixir_agent_request.exs \
  /absolute/path/to/aauth-go/interop/elixir-agent-request.json
```

The generator reads the comparator commit itself and refuses tracked changes
to its AAuth source or dependency files, so the recorded revision identifies
the code that actually emitted the vector.

The JKT-JWT pair retains the same boundary. The active Go-origin vector carries
a fully specified `Ed25519` durable key and delegated request key and passes the
Go verifier. The historical Elixir-origin vector carries `EdDSA` in its signed
header and is retained to prove that the new verifier refuses it.

Generate the Elixir request and verify it through the Go test:

```sh
cd /absolute/path/to/sidecat-beam
mix run /absolute/path/to/aauth-go/interop/generate_elixir_jkt_jwt_request.exs \
  /absolute/path/to/aauth-go/interop/elixir-jkt-jwt-request.json

cd /absolute/path/to/aauth-go
go test ./... -run TestLegacyDraft06ElixirJKTJWTRequestIsRetainedButRejected
```

Generate the reciprocal Go request and verify it through Elixir:

```sh
cd /absolute/path/to/aauth-go
go run ./internal/interop/cmd/generate --profile jkt-jwt-request \
  interop/go-jkt-jwt-request.json

cd /absolute/path/to/sidecat-beam
mix run /absolute/path/to/aauth-go/interop/verify_go_jkt_jwt_request.exs \
  /absolute/path/to/aauth-go/interop/go-jkt-jwt-request.json
```

The active Go vector proves self-issued key delegation and request-key binding
inside this implementation. It is not a cross-language interoperability claim.
The AP enrollment lookup, refresh policy, replay custody, and returned agent
token are proved separately by the Go bootstrap journey because the bootstrap
draft deliberately leaves those deployment choices informational.
