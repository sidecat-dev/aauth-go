# Use it in your service

A **Resource** is the API receiving a request. An **Agent** is its caller.
An **Agent Provider (AP)** signs an Agent token that identifies the Agent and
binds its public key. The Agent then signs the HTTP request with its own key.
The Resource checks both signatures before calling your application.

## Verify an Agent at your HTTP endpoint

Use `resource.NewAgentIdentity` when your service accepts Agent identity
without a person's authorization. This function returns a handler you can
mount on your application's HTTPS server:

```go
func agentResource(keys signaturekey.KeyResolver, clock aauth.Clock, app http.Handler) (http.Handler, error) {
	server, err := resource.NewAgentIdentity(resource.AgentIdentityConfig{
		Issuer: "https://resource.example", KeyResolver: keys, Clock: clock,
		Protected: app,
	})
	if err != nil {
		return nil, err
	}
	return server.Handler(), nil
}
```

Imports: `net/http`, `aauth "gitlab.com/sidecat-dev/aauth-go"`, and the
module's `resource` and `signaturekey` packages. Set `Issuer` to your
Resource's HTTPS identifier. In a running service, pass `aauth.SystemClock{}`;
tests can pass `aauth.ClockFunc` for a fixed time.

`keys` resolves **AP signing keys**, not the Agent's request key. For one
configured AP, an exact in-memory trust map is enough:

```go
func providerKeys(key jose.JWK) signaturekey.StaticKeyResolver {
	return signaturekey.StaticKeyResolver{
		{Issuer: "https://agents.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: key.Kid}: key,
	}
}
```

Here `key` is the AP public key you configured, represented as a JSON Web Key
(`jose.JWK`). The map key is `(issuer, discovery document, key ID)`.
`aauth.AgentDiscoveryDocument` is `"aauth-agent.json"`: the token's `dwk`
claim selects that well-known document. For network discovery, use
`signaturekey.NewHTTPKeyResolver` with your HTTP client, clock and `Admit`
callback, which decides which endpoints may be contacted.

Inside `app`, call `resource.AgentPrincipalFromContext(r.Context())` to get
the verified Agent identity. Apply your own access policy there. Identity
does not grant person-authorized scopes. The runnable example allows only
`aauth:reader@agents.example`; it owns no listener, persistence or TLS setup.

## Check a token without an HTTP request

When you already have a compact Agent JWT, the Core call is:

```go
claims, err := aauth.VerifyAgentToken(context.Background(), token, keys, clock)
if err != nil {
	return err
}
```

`token` is the received JWT; `keys` and `clock` are the same dependencies as
above. This verifies the token's signature and Core claims, including expiry;
`claims.Subject` is the verified Agent identifier.
It does **not** verify possession of the Agent's private key on an HTTP request,
consult a revocation store, or decide access to your operation. Use the Resource
handler for request verification.

All Go snippets execute in [the complete example](example/verifyagent/main.go).
From a checkout:

```sh
go run ./example/verifyagent
go test ./example/verifyagent -count=1
```

```text
Token verified: aauth:reader@agents.example
Request verified: aauth:reader@agents.example
```

The example creates synthetic AP and Agent keys and a fixed clock.
[Its tests](example/verifyagent/main_test.go) also reject a modified or
expired token, an untrusted AP key, a missing request proof, a wrong proof key
and a changed request method.

## Choose the next API

A **Person Server (PS)** represents the person's identity and decisions.
An **Access Server (AS)** is a separate authorization issuer when the Resource
uses four-party federation.

| Your service needs | Resource constructor |
| --- | --- |
| Agent identity, without person authorization | `NewAgentIdentity` |
| Person identity, without an authorization grant | `NewPersonIdentity` |
| Auth tokens issued directly by a PS | `NewPSAuthorization` |
| Auth tokens issued by a separate AS | `NewFederatedAuthorization` |
| Resource-owned opaque sessions | `NewResourceManaged` |
| Event subscription and delivery service | `NewEventService` (a separate service) |

The root `aauth` package exposes `MintAgentToken`, `VerifyAgentToken`,
`VerifyPersonToken`, `VerifyResourceToken` and `VerifyAuthToken` for individual
tokens. `VerifyPresentedToken` binds the token previously shown to a Resource
to that Resource's authorization request. These Core checks do not enforce
R3 or Budget claims; the [role examples](JOURNEYS.md) show that composition.
See the [glossary](GLOSSARY.md) for the token fields and companion terms.

## Versions and local development

`go get gitlab.com/sidecat-dev/aauth-go` records a published version in your
module. Review and commit `go.mod` and `go.sum`; these editor drafts and APIs
are still evolving. The standalone `walkthrough/` modules deliberately pin
published pseudo-versions. Their tests exercise those versions, not this
checkout.

To try this checkout from a consumer module placed beside it:

```sh
go mod edit -replace=gitlab.com/sidecat-dev/aauth-go=../aauth-go
go mod tidy
```
