# Independent Resource interoperability walkthrough

This standalone module has an AAuth Go Agent call the AAuth project's live
[`whoami.aauth.dev`](https://whoami.aauth.dev/) Resource. That Resource is an
independent TypeScript implementation.

The `call` command exercises one small boundary:

1. AAuth Go mints an `aa-agent+jwt` for a generated Agent key;
2. ordinary HTTPS hosting exposes only the Agent Provider metadata and JWKS;
3. AAuth Go signs `GET https://whoami.aauth.dev/` with that token and key; and
4. the independent Resource discovers the provider key, verifies both token
   and request, and returns the exact Agent identity.

It does not exercise person identity, authorization, an Access Server, R3, or
the five-surface interoperability demo profile.

The `serve` command and the `typescript-agent` script exercise the reverse
direction: the official TypeScript `@aauth/agent` package obtains Person and
Auth tokens from a Go Person Server and creates one durable note at a Go
Resource. This module pins an older published Go version in its `go.mod`.

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

## Run the TypeScript Agent against Go authorization roles

Choose two HTTPS origins: one for the static Agent Provider documents and one
for the collocated Go Person Server and Resource. The Go service listens only
on loopback; terminate public TLS with Caddy or another reverse proxy.

```sh
agent_origin=https://agent.example
service_origin=https://service.example
agent_state="$(mktemp -d)"
service_state="$(mktemp -d)"

./aauth-interop init \
  --state "$agent_state" \
  --issuer "$agent_origin" \
  --person-server "$service_origin" >"$agent_state/init.json"

./aauth-interop agent-config --state "$agent_state" >"$agent_state/typescript-agent.json"
chmod 600 "$agent_state/typescript-agent.json"
```

Publish only `$agent_state/public` at `agent_origin`. Keep every other file in
`agent_state` private. A minimal Caddy shape is:

```caddyfile
agent.example {
  root * /srv/aauth-agent-public
  file_server
}

service.example {
  reverse_proxy 127.0.0.1:8080
}
```

Start the Go roles with the exact Agent identity printed by `init`:

```sh
agent_id="$(jq -r .agent "$agent_state/init.json")"

./aauth-interop serve \
  --state "$service_state" \
  --listen 127.0.0.1:8080 \
  --origin "$service_origin" \
  --agent-issuer "$agent_origin" \
  --agent "$agent_id"
```

In another shell, install the pinned official Agent package and create one
protected note:

```sh
cd typescript-agent
npm ci
npm test
node call.mjs \
  --config "$agent_state/typescript-agent.json" \
  --resource "$service_origin/notes" \
  --request-key interop-write-1 \
  --text "hello from the TypeScript Agent"
```

Success names the Agent, the Go-established person, the retained note, and a
consequence count of one. Repeating the same request key and text returns the
same note with `replayed: true`; changing the text under that key is refused.
The Go role keys are currently process-scoped. A restart can issue fresh
tokens and recover the durable application consequence, but it does not retain
or continue outstanding role credentials across that restart.

The official Agent does not yet honor arbitrary Resource-declared additional
signature components on its initial request
([`aauth-dev/packages-js` issue #24](https://github.com/aauth-dev/packages-js/issues/24)).
This walkthrough keeps the replay
key inside the signed JSON body, where `content-digest` binds it together with
the note, rather than weakening replay identity to fit that limitation.

## Verify the local construction

```sh
go test ./... -count=1
go test -race ./... -count=1
go vet ./...

cd typescript-agent
npm ci
npm test
```

The Go tests check generated metadata, JWKS, token, HTTP Message Signature,
and the identity-response check. The JavaScript unit test stubs `fetch` and
checks the Agent script's response handling; it does not call the Go roles.
A live run against the other implementation needs the public-TLS setup above.
