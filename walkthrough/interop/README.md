# Independent Resource interoperability walkthrough

This standalone module has an AAuth Go Agent call the AAuth project's live
[`whoami.aauth.dev`](https://whoami.aauth.dev/) Resource. That Resource is an
independent TypeScript implementation.

The walkthrough proves one deliberately small boundary:

1. AAuth Go mints an `aa-agent+jwt` for a generated Agent key;
2. ordinary HTTPS hosting exposes only the Agent Provider metadata and JWKS;
3. AAuth Go signs `GET https://whoami.aauth.dev/` with that token and key; and
4. the independent Resource discovers the provider key, verifies both token
   and request, and returns the exact Agent identity.

It does not exercise person identity, authorization, an Access Server, R3, or
the five-surface interoperability demo profile.

## Build

```sh
cd walkthrough/interop
go build -o ./aauth-interop .
```

The module has no `replace` directive and imports only the published AAuth Go
API.

## Initialize an Agent Provider and Agent

Choose an HTTPS issuer you control. Its hostname also becomes the Agent
identifier's domain.

```sh
interop_state="$(mktemp -d)"

./aauth-interop init \
  --state "$interop_state" \
  --issuer https://aauth-interop.example
```

The command creates:

- `private.json`, mode `0600`, containing the generated private keys and
  short-lived Agent token; and
- `public/`, containing only `/.well-known/aauth-agent.json` and `/jwks.json`.

Publish the contents of `public/` at the exact issuer origin using an ordinary
HTTPS static server. The provider private key does not need to be online.
The generated Agent token lasts ten minutes, so initialize immediately before
the call.

## Call the independent Resource

```sh
./aauth-interop call \
  --state "$interop_state" \
  --target https://whoami.aauth.dev/
```

Success is one compact result naming the HTTP status, provider issuer, Agent,
and target. The command rejects a response unless the returned `(iss, sub)`
exactly matches the generated identity.

## Verify the local construction

```sh
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
```

The automated test proves the generated metadata, JWKS, token, HTTP Message
Signature, and identity-response check. The independent claim requires the
live call above; a same-implementation local test cannot establish it.
