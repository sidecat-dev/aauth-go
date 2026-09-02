# Independent Resource interoperability walkthrough

This standalone module has an AAuth Go Agent call the AAuth project's live
[`whoami.aauth.dev`](https://whoami.aauth.dev/) Resource. That Resource is an
independent TypeScript implementation.

The qualified walkthrough proves one deliberately small boundary:

1. AAuth Go mints an `aa-agent+jwt` for a generated Agent key;
2. ordinary HTTPS hosting exposes only the Agent Provider metadata and JWKS;
3. AAuth Go signs `GET https://whoami.aauth.dev/` with that token and key; and
4. the independent Resource discovers the provider key, verifies both token
   and request, and returns the exact Agent identity.

It does not exercise person identity, authorization, an Access Server, R3, or
the five-surface interoperability demo profile.

The same module also contains the next, not-yet-qualified interoperability
path: the official TypeScript `@aauth/agent` package obtains Person and Auth
tokens from a Go Person Server and creates one durable note at a Go Resource.
The instructions below describe that path without claiming it has crossed the
live boundary yet.

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
The Go role keys are currently process-scoped, so this path proves independent
wire interoperability and a durable application consequence, not role restart
recovery.

## Verify the local construction

```sh
go test ./... -count=1
go test -race ./... -count=1
go vet ./...

cd typescript-agent
npm ci
npm test
```

The automated test proves the generated metadata, JWKS, token, HTTP Message
Signature, and identity-response check. The independent claim requires the
live call above; a same-implementation local test cannot establish it.

## External qualification

On 2026-09-01, published AAuth Go source
`00eb6f0a2a3000ff96a44b988059acea3c2babf0` generated a short-lived public
Agent Provider and called the live TypeScript Resource built from
[`aauth-dev/whoami`](https://github.com/aauth-dev/whoami) revision
`9f023d27ba51e0c11018e416b23140fbea14c9ff`. The Resource returned HTTP 200
with the exact Go-generated provider issuer and Agent identifier. The
temporary provider origin, DNS record, private state, and host were removed
after the call.
