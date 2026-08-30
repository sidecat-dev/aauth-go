# AAuth for Go

`auth-go` is a Go implementation of the current AAuth editor drafts. The
current implementation covers direct Agent and Person identity access,
Resource-managed opaque sessions, immediate and explicitly deferred three-party
PS authorization, one four-party federated flow, Person-Server-hosted
person-token interaction, both specified deliveries of the auth-token
requirement (`401` retry and Resource-held `202`), bounded three-party
auth-token revocation with explicit re-authorization, and the HTTP
Signature-Key behavior those paths need.

It is not a complete AAuth implementation, an interoperability claim, or an
official conformance suite. The supported boundary is explicit so applications
can use the implemented path without assuming that unfinished parts of the
specification family are present.

## Availability

The module requires Go 1.24 or later.

This implementation has not yet been released under the
`github.com/aauth-dev/auth-go` module path. Test it from this checkout; do not
use `go get github.com/aauth-dev/auth-go` to obtain this code until a revision
containing it is published there.

## What is implemented

The implemented access paths are:

```text
Agent Provider -> Agent -------------------------------> Resource
                       \--- Resource-owned interaction -> Resource session
                       \-> Person Server ---------------> Resource
                                         \--------------> Resource
                                          \-> Access Server -> Resource
```

It covers:

- minting and verifying current agent, person, resource, and auth tokens;
- Ed25519 JWKs, RFC 7638 thumbprints, and compact JWS;
- the `jwt` and `jwks_uri` Signature-Key paths used by the flow;
- signed HTTP requests with exact covered-component and body-digest checks;
- admitted metadata and JWKS discovery with bounded caching;
- composable `http.Handler` implementations for all four server roles;
- separate Agent-identity, Person-identity, Resource-session, and scoped-auth
  principals at the Resource application boundary;
- explicit person binding, person-record resolution, consent, trust, and
  authorization policy callbacks;
- copy-safe additional agent and auth-token claims at the policy seams that
  can use them;
- host-supplied person-token, PS-authorization, issued-auth-token,
  Resource-auth-token-status, Resource-session, and held-invocation store
  contracts; and
- a small agent client that performs each protocol step explicitly.

## Packages

| Package | Responsibility |
| --- | --- |
| `aauth` | Core identifiers, token claims, minting, verification, and context checks |
| `jose` | The selected Ed25519 JWK and compact-JWS profile |
| `signaturekey` | HTTP request proof, Signature-Key credentials, and issuer-key discovery |
| `agentprovider` | Agent-token issuance plus Agent Provider metadata and JWKS |
| `agent` | Explicit Core calls, including direct Agent identity, Resource-session use, PS consent, one interaction poll, and one held-invocation poll; no hidden loops or retries |
| `personserver` | Immediate person-token issuance plus either direct PS authorization or AS federation; optional domain-specific stores support person-token interaction, deferred three-party consent, and exact issued-token revocation |
| `resource` | Direct Agent or Person identity protection, Resource-owned opaque sessions, explicit PS or federated authorization, resource-token issuance, observed-token revocation, and held-request completion |
| `accessserver` | Person-Server-authenticated policy and auth-token issuance |

Each role is an ordinary Go package. Applications supply keys, clocks, HTTP
clients, policy functions, and storage rather than configuring a framework
owned by this module.

## Use direct identity access

Direct modes do not require an Access Server. Each constructor accepts only the
dependencies its credential mode uses.

```go
agentResource, err := resource.NewAgentIdentity(resource.AgentIdentityConfig{
	Issuer:      "https://resource.example",
	KeyResolver: resolver,
	Clock:       clock,
	Protected:   handler,
})

response, err := client.CallAsAgent(ctx, request)
```

`NewAgentIdentity` places an `AgentPrincipal` in the handler context.
That principal distinguishes a top-level Agent from a one-level sub-agent by
retaining `ParentAgent`. `CallAsAgent` discovers the Resource metadata first;
`CallAsAgentWithComponents` accepts the exact additional signature components
and makes no metadata request, including when the Resource publishes none.
Sub-agents can use either identity-only call. The client refuses their direct
Person Server calls because Core requires those authorization steps to be
parent-mediated. When an Agent token names no Person Server, either call closes
a returned `requirement=person-token` response and reports that the requirement
cannot be satisfied.
`NewPersonIdentity` verifies a directed person token, calls `ResolvePerson`,
and places a scope-free `PersonPrincipal` in the handler context.
`NewPSAuthorization` and `NewFederatedAuthorization` both place a scope-bearing
`AuthPrincipal`; their explicit configs distinguish who issues the auth token.
These principal values remain distinct because identity and authorization are
different claims.

## Use a Resource-managed session

`NewResourceManaged` implements the direct two-party path. The Resource
verifies an Agent-token request, applies its own policy, and may return an
opaque `AAuth-Access` session immediately or after its own authenticated
interaction. No Person Server, Access Server, person token, resource token, or
auth token participates.

For synchronous policy, leave `Interaction` at its zero value, supply
`AuthorizeImmediately`, and provide the small `SessionStore` interface. To
fall back to user interaction when immediate policy declines, configure
`Interaction` and provide `DeferredSessionStore` instead.

The Agent calls each step explicitly:

```go
request.Header.Set("AAuth-Capabilities", "interaction") // caller opt-in
started, err := client.BeginResourceSession(ctx, request)
if err != nil {
	return err
}
var session agent.ResourceSession
remember := func(result agent.ResourceSessionResult) {
	if replacement, ok := result.Session(); ok {
		session = replacement
		persist(session.State()) // do this before handling Failure
	}
}
remember(started)
response, _ := started.Response()
if failure := started.Failure(); failure != nil {
	if response != nil {
		response.Body.Close()
	}
	return failure
}
if pending, pendingOK := started.Pending(); pendingOK {
	showInteraction(pending.InteractionURL(), pending.InteractionCode())
	completed, err := client.PollResourceSession(ctx, pending) // one signed GET
	if err != nil {
		return err
	}
	remember(completed)
	if failure := completed.Failure(); failure != nil {
		if failed, ok := completed.Response(); ok {
			failed.Body.Close()
		}
		return failure
	}
	if next, ok := completed.Pending(); ok {
		return schedulePoll(next) // caller chooses when to make the next GET
	}
	pollResponse, _ := completed.Response()
	if pollResponse != nil && (pollResponse.StatusCode == 429 || pollResponse.StatusCode == 503) {
		defer pollResponse.Body.Close()
		return schedulePollAfter(pending, pollResponse.Header.Get("Retry-After"))
	}
	if pollResponse != nil {
		pollResponse.Body.Close()
	}
	if session.Token() == "" {
		return errors.New("Resource returned no session")
	}
	used, err := client.DoWithResourceSession(ctx, request, session)
	if err != nil {
		return err
	}
	remember(used)
	response, _ = used.Response()
	if failure := used.Failure(); failure != nil {
		if response != nil {
			response.Body.Close()
		}
		return failure
	}
}
if response != nil && (response.StatusCode == 429 || response.StatusCode == 503) {
	defer response.Body.Close()
	return retryOriginalAfter(response.Header.Get("Retry-After"))
}
if response == nil {
	return errors.New("Resource returned neither a response nor a session")
}
if session.Token() == "" {
	response.Body.Close()
	return errors.New("Resource returned no session")
}
defer response.Body.Close()
```

An immediate result already contains the original application response; do not
send that request again. A pending interaction does not retain the application
request, so after approval the caller explicitly sends it once with the new
session.

`BeginResourceSession` preserves the caller's `AAuth-Capabilities` field;
absence means the Agent cannot drive interaction. It and
`DoWithResourceSession` discover Resource metadata, then make the signed
application call. Their `WithComponents` variants accept the exact signature
profile and make one HTTP exchange with no metadata fetch.
When a pending handle reports additional signature components, supply fresh
header values explicitly:

```go
header := http.Header{"X-Request-ID": []string{"poll-42"}}
completed, err := client.PollResourceSessionWithComponents(
	ctx, pending, header, pending.AdditionalSignatureComponents(),
)
```

The interaction code only correlates the browser visit. The host separately
authenticates the person, then calls `ApproveSessionInteraction`,
`DenySessionInteraction`, or `InvalidateSessionInteraction`. A
`DeferredSessionStore` retains that decision and the session before the Agent
can observe either one. Every session call carries the current AP-issued agent
token and a proof that covers `Authorization`.

The client does not open the interaction URL, sleep, poll repeatedly, or
replay the original application request. A replacement `AAuth-Access` header
produces a new `ResourceSession`. A recognized Signature-Key or AAuth failure
is returned by `ResourceSessionResult.Failure`, not as the method's Go error,
so the caller can persist that replacement first. The Go error means no valid
HTTP outcome could be formed. `429` and `503` poll responses remain
caller-owned so their `Retry-After` fields can drive the next explicit call.

Persist `session.State()`, including its stable Agent identity, and restore it
with `client.RestoreResourceSession(state)`. Restore performs no network call
and permits a new Agent token and proof key only when the AP, Agent, and parent
Agent identifiers still match.

## Use immediate PS authorization

Three-party access needs no Access Server. The Resource issues each resource
token to the verified person-token issuer. The Person Server's policy selects
a subset of the requested scopes and a lifetime of at most one hour.

```go
protectedResource, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
	Issuer: resourceID, SigningKey: resourceKey, KeyResolver: resolver,
	Clock: clock, NewID: newResourceTokenID,
	ScopeDescriptions: map[string]string{"records.read": "Read records"},
	RequiredScopes: requiredScopes, ResolvePerson: resolvePerson,
	Protected: handler,
})

people, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
	Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver,
	Clock: clock, NewID: newTokenID, Tokens: personTokens,
	BindPerson: bindPerson,
	Authorize: func(ctx context.Context, request personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
		return personserver.AuthorizationDecision{Scopes: request.Scopes, Lifetime: 30 * time.Minute}, nil
	},
})
```

The Agent uses the same explicit `PersonToken`, `Authorize`, `Exchange`, and
`Do` calls in three- and four-party access. The signed auth token's `dwk`
selects the verified issuer role; the Agent separately binds `iss` to the
resource-token audience. Each explicit Resource constructor enforces the role
it accepts. This remains unambiguous when a PS and AS share one origin.

## Revoke and explicitly re-authorize

Three-party revocation is optional. Configure the Person Server with an
`IssuedAuthTokenStore` and the Resource with an `AuthTokenStatusStore`. The
Person Server retains each issued token's reference before release; the
Resource recognizes a token on its first otherwise-valid protected use.

```go
people, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
	// ordinary three-party fields omitted
	Revocation: &personserver.AuthTokenRevocationConfig{
		IssuedTokens: issuedTokens,
		HTTPClient:   httpClient,
		Admit:        admitEgress,
	},
})

protectedResource, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
	// ordinary three-party fields omitted
	AuthTokenStatuses: authTokenStatuses,
})

err = people.RevokeIssuedAuthToken(ctx, aauth.TokenReference{
	Issuer: personServerID,
	JTI:    authClaims.JTI,
})
```

`Admit` runs before the metadata GET and again before the metadata-selected
revocation endpoint can be contacted; hosts use it to apply their egress
policy. The supplied HTTP client is cloned; revocation does not use its ambient
cookie jar or redirect callback, and the caller's client remains unchanged.
The transport still owns DNS and connection policy.

`RevokeIssuedAuthToken` reads Resource metadata, makes one revocation POST, and
never retries. While the token records remain retained, a lost response is
safe to retry explicitly because the Resource returns `200` for both a new and
an already-retained revocation. After expiry, a removed record may instead be
unrecognized. The Agent re-authorizes through the ordinary
`Authorize` and `Exchange` calls; it does not refresh or replace credentials
automatically. `RevokeIssuedAuthToken` is the convenience call for a Resource
with no extra signature fields. If metadata advertises additional components,
that call stops before the POST and names the missing header; use
`RevokeIssuedAuthTokenWithHeaders` to supply fresh values. This cut does not
revoke a token before the Resource has first
recognized it, and it does not implement four-party, Agent-token, mission, or
session revocation.

## Complete deferred PS consent

Three-party authorization can park after the PS has verified the Agent proof,
resource token, requested scopes, and retained person-token lineage. Configure
`RequireAuthorizationInteraction` with a `DeferredAuthorizationStore`; both nil
keep the immediate path above. `Authorize` may be nil for a deferred-only
Person Server. In that composition the interaction policy must select an
interaction for every verified request; declining without an immediate policy
returns `500 server_error` without creating pending state.

```go
result, err := client.BeginExchange(ctx, agent.ExchangeRequest{
	PersonServer:  personServerID,
	ResourceToken: resourceToken,
	Capabilities:  []string{"interaction"},
})
if err != nil {
	return err
}
if authToken, ok := result.Token(); ok {
	return useAuthToken(authToken)
}
pending, ok := result.Pending()
if !ok {
	return errors.New("PS returned no usable exchange result")
}
retainPending(pending)
if failure := result.Failure(); failure != nil {
	return failure
}
if pending.Requirement() == aauth.RequirementInteraction {
	showInteraction(pending.InteractionURL(), pending.InteractionCode())
}
```

The interaction page passes the URL reference and entered code to
`ConsumeAuthorizationInteractionCode`. That only correlates the request. After
authenticating the person through its own channel, the host calls
`ApproveAuthorizationInteraction`, `DenyAuthorizationInteraction`,
`AbandonAuthorizationInteraction`, or `FailAuthorizationInteraction`.
`ResumeAuthorizationInteraction` reconstructs the host handle after the Server
is recomposed around the same store. The store atomically counts wrong code
presentations and closes the interaction at the fixed three-attempt bound. Once
the correct code has correlated the host visit, later code submissions cannot
change that interaction. Same-scope-set, same-lifetime approval races converge
on the first complete retained token and decision.

The caller makes each poll explicitly:

```go
result, err = client.PollExchange(ctx, pending) // exactly one signed GET
if err != nil {
	return err // includes denied, abandoned, expired, server_error, and invalid_code
}
response, responseOK := result.Response()
if responseOK { // caller owns every returned response body
	defer response.Body.Close()
}
next, pendingOK := result.Pending()
if pendingOK {
	retainPending(next)
}
if failure := result.Failure(); failure != nil {
	return failure // the retained continuation may still be polled explicitly
}
if responseOK {
	return schedulePoll(next) // next.RetryAfter() includes the required backoff
}
if pendingOK {
	return schedulePoll(next)
}
authToken, _ := result.Token()
return useAuthToken(authToken)
```

`BeginExchange` sends `Prefer: wait=0`; neither method sleeps, opens a browser,
or loops. A recomposed Client with the same Agent Provider, Agent identifier,
proof key, Person Server, and retained resource-token context can continue the
in-memory handle. This cut does not serialize `PendingExchange` across a client
process restart. `PendingExchange.Requirement()` reports interaction, approval,
clarification, an extension value, or no requirement. Only interaction carries
an interaction URL and code. `ExchangeResult.Failure()` explicitly reports a
verified but unsupported requirement while preserving its pending continuation.
Clarification answers and initial payment continuation are not implemented yet.
An initial `503` is returned as a caller-owned response without `Pending`; the
caller applies its `Retry-After` and repeats `BeginExchange` explicitly.
Role handlers use the registered `500 server_error` for internal store or
retained-result failures. They reserve `503` for a genuinely retryable response
that supplies an explicit `Retry-After` contract.

## Complete a person-token interaction

`PersonToken` returns either a verified token or a verified pending handle.
The client never opens the interaction URL or polls automatically.

```go
result, err := client.PersonToken(ctx, agent.PersonTokenRequest{
	PersonServer: "https://person.example",
	Resource:     "https://resource.example",
})
if err != nil {
	return err
}
pending, ok := result.Pending()
if !ok {
	personToken, _ := result.Token()
	return usePersonToken(personToken)
}

showInteraction(pending.InteractionURL(), pending.InteractionCode())
result, err = client.PollPersonToken(ctx, pending) // one signed GET
```

The interaction URL ends in the pending reference. At that authenticated UI,
the host passes the reference and entered code to
`ConsumePersonTokenInteractionCode`. A match correlates the request but does
not authorize it. After authenticating the person, the host calls
`ApprovePersonTokenInteraction` or `DenyPersonTokenInteraction`. The host also
rate-limits failed entries for that reference and calls
`InvalidatePersonTokenInteraction` when its bound is reached.

`ResumePersonTokenInteraction` rebuilds the host handle from the reference
after a `Server` value is recomposed around the same store. This repository
tests that composition boundary with in-memory stores; it does not supply a
durable adapter or prove process-restart persistence.

## Verify an auth token

Signature verification is only the first check. Bind the verified claims to
the issuer role, resource, person, request key, and required scopes before
using them.

```go
claims, err := aauth.VerifyAuthToken(ctx, compact, resolver, aauth.SystemClock{})
if err != nil {
	return err
}
return aauth.ValidateCurrentAuthTokenContext(
	claims,
	aauth.AuthTokenContext{
		Issuer: "https://access.example",
		DiscoveryDocument: aauth.AccessDiscoveryDocument,
		Resource: "https://resource.example",
		PersonServer: "https://person.example",
		Subject: "person-123",
		RequestKey: agentPublicJWK,
		RequiredScopes: []string{"records.read"},
	},
)
```

## Complete a Resource-held call

`Begin` boxes a verified pending result. The caller obtains the auth token and
chooses when to make one poll; the client never sleeps or loops internally.

```go
result, err := client.Begin(ctx, agent.InitialCall{
	Request: request, PersonToken: personToken,
})
if err != nil {
	return err
}
pending, ok := result.PendingAuthToken()
if !ok {
	// Handle result.Response or result.AuthorizationRequired instead.
	return errors.New("resource did not hold the invocation")
}
authToken, err := client.Exchange(ctx, agent.ExchangeRequest{
	PersonServer: personServer, ResourceToken: pending.ResourceToken(),
})
if err != nil {
	return err
}
response, err := client.PollAuthToken(ctx, agent.AuthTokenPoll{
	Pending: pending, AuthToken: authToken,
})
if err != nil {
	return err
}
defer response.Body.Close() // Every returned response is caller-owned.
```

To offer this delivery, a Resource supplies `resource.HeldInvocationStore`
and positive request-body, response-body, and combined header/trailer limits.
`HoldAuthTokenRequest` can select held or baseline delivery for each verified
person-token request; nil selects held delivery for every request on that
Server. The store atomically claims one invocation and retains its logical
response before the Resource publishes that response. This repository defines
and tests the contract; it does not provide a database adapter.

Wait at least `pending.RetryAfter()` before the first poll. `PollAuthToken` is
deliberately one-shot. It returns an application response, another `202`,
`429`, or `503` without consuming its body. The caller owns that body, reads
the returned `Retry-After`, and decides whether and when to poll again.

Held delivery captures an ordinary finite HTTP exchange. It accepts bounded
request bodies and headers, and it preserves status, end-to-end headers, body,
and valid trailers. It rejects `CONNECT`, request trailers, transfer encoding,
connection-close semantics, streaming and full-duplex response controls,
hijacking, server push, `text/event-stream`, and hop-by-hop response framing.
It does not retain the original `RemoteAddr`, TLS state, or arbitrary request
context values. Execution uses a fresh context bounded by the auth token's
remaining verified lifetime and detached from poll cancellation. Middleware
must re-establish any application context it needs from retained, authenticated inputs. Use
`HoldAuthTokenRequest` to select baseline `401` delivery for a route that needs
unsupported HTTP or context behavior.

## Run the examples

The direct Agent-identity example uses no Person Server or Access Server:

```sh
go run ./example/agentidentity
```

Expected output:

```text
AAuth agent identity flow complete: aauth:reader@agents.example
```

The Resource-session example adds Resource-owned interaction and an opaque
proof-bound session, still without a Person Server or Access Server:

```sh
go run ./example/resourcesession
```

Expected output:

```text
AAuth Resource-managed session complete: person-123 has records.read
```

The three-party example uses a Person Server for identity and consent but no
Access Server:

```sh
go run ./example/threeparty
```

Expected output:

```text
AAuth three-party flow complete: person-123 has records.read
```

The deferred-consent example runs the same topology but retains the verified
PS request until the host separately authenticates the person and approves it:

```sh
go run ./example/psconsent
```

Expected output:

```text
AAuth deferred PS consent complete: person-123 has records.read
```

The revocation example shows a lost response, explicit idempotent retry,
Resource recomposition, refusal of the old token, and explicit
re-authorization:

```sh
go run ./example/revocation
```

Expected output:

```text
auth-token-1 accepted
auth-token-1 revocation response lost; explicit retry succeeded after Resource recomposition
auth-token-1 refused: 403 access_denied
auth-token-2 accepted after explicit re-authorization
```

The four-party example composes all role handlers behind an in-process logical
transport. It issues all four token types, performs the Person Server to Access
Server exchange, and calls a protected HTTP handler.

```sh
go run ./example/fourparty
```

Expected output:

```text
AAuth four-party flow complete: person-123 has records.read
```

The examples use generated keys, fixed logical HTTPS origins, and in-memory
stores. They are executable documentation, not deployment templates.

## Current boundaries

The current implementation does not provide a general deferred-authorization
engine, interaction relay, clarification, automatic polling, token renewal or
general token revocation, parent or sub-agent delegation, call chaining, R3,
Events, Budgets, Bootstrap, or the complete interoperability demo profile. Its
narrow deferred paths are person-token interaction, three-party PS consent,
Resource-managed interaction, and Resource-held auth-token delivery. Its
revocation path is limited to a PS-issued three-party auth token already
recognized by the Resource.

The next complete Core seam is parent-mediated sub-agent person- and auth-token
handling: the parent requests credentials bound to the sub-agent key, and the
sub-agent uses them itself. The first companion seam after the remaining Core
paths is one MCP-only R3 direct grant. [Architecture](ARCHITECTURE.md) assigns
the other companion boundaries without creating placeholder packages.

The role packages do not provide TLS listeners, key storage, a durable replay
store or multi-process coordination. Hosts supply `DeferredTokenStore`,
`DeferredAuthorizationStore`, `IssuedAuthTokenStore`, `AuthTokenStatusStore`,
`SessionStore` (or `DeferredSessionStore` when interaction is enabled), and
`HeldInvocationStore`; this repository supplies no durable adapter. The agent
client does not cache credentials, retry
consequences, or automatically follow a deferred response. A deployment must
supply those behaviors where its threat model and availability requirements
need them.

An approved pending person token is verified before its terminal response is
consumed. The signing key used for that token must remain trusted and
resolvable until delivery or expiry. The built-in Person Server JWKS publishes
only the active key, so a host that rotates keys while interactions are
outstanding must provide a resolver and JWKS policy that retains the required
prior key.

Each role rejects known mission, delegation, chaining, unsupported deferred,
R3, and Budget inputs that this cut cannot evaluate. Unknown additive JSON
members remain available for future extensions instead of forcing a protocol
version flag day.

The HTTP key resolver admits each metadata and JWKS URL through caller policy,
rejects redirects, and bounds response sizes, cache entries, concurrent work,
and fetch time. Its caller-supplied
`http.Transport` must also resolve and pin the admitted host safely, reject
private or otherwise forbidden resolved addresses, and prevent DNS rebinding;
checking the URL string alone is not sufficient. Keep signing keys outside
this module, use HTTPS at the process boundary, and do not treat a valid
signature as an authorization decision.

The Agent and Person Server also use caller-supplied HTTP clients for role
requests. Callers must give operations finite contexts and transports with the
same destination and connection controls; URL validation is not a network
sandbox.

Independent implementation interoperability has not yet been demonstrated.
The editor drafts continue to change, so applications should pin a module
revision and review the documented specification baseline before deployment.

## Documentation

- [Architecture](ARCHITECTURE.md) explains package ownership, direct Resource
  sessions, person-token interaction, and both auth-token requirement
  deliveries.
- [Conformance](CONFORMANCE.md) maps implemented behavior to the editor drafts
  and lists open coverage.
- [Specification baseline](SPECIFICATIONS.md) identifies the exact source
  revisions used by this implementation.
- [Interpretations](INTERPRETATIONS.md) records choices where the source does
  not determine one implementation.
- [Specification feedback](SPEC-FEEDBACK.md) records reproducible questions
  for the editors.
- [Security policy](SECURITY.md) explains how to report vulnerabilities.
- [Contributing](CONTRIBUTING.md) describes the source-grounded development
  and verification workflow.

## Verify the repository

```sh
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
```
