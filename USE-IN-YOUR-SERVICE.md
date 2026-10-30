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
		AdditionalSignatureComponents: []string{"content-digest"},
		Protected:                     app,
	})
	if err != nil {
		return nil, err
	}
	return server.Handler(), nil
}
```

Imports: `net/http`, `aauth "gitlab.com/sidecat-dev/aauth-go"`, and the
module's `resource` and `signaturekey` packages. Set `Issuer` to your
Resource's public HTTPS identifier: a lowercase DNS name, without a port,
path, query or fragment. The handler refuses a different request authority
with HTTP 421. In a running service, pass `aauth.SystemClock{}`;
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

## Protect request bodies

The default proof covers method, authority, path and `Signature-Key`, plus
the query and Authorization field when present. **Nonempty content also covers
SHA-256 Content-Digest and Content-Type when present.** The signer computes the
digest; verification checks the actual bytes before policy or dispatch.
Missing coverage returns `401` with `Signature-Error: invalid_input` and
`required_input`; changed bytes or a mismatched digest return `401` with
`Signature-Error: invalid_signature`.

The handler above additionally requires `content-digest` on *every* request,
including empty ones. Its caller supplies that unconditional component:

```go
func signAgentRequest(request *http.Request, key jose.SigningKey, token string, clock aauth.Clock) error {
	return signaturekey.SignJWTRequestWithOptions(request, key, token, clock, signaturekey.SignOptions{
		AdditionalComponents: []string{"content-digest"},
	})
}
```

The signer preserves the body for transport. To use only the nonempty-body
default, omit `content-digest` from `AdditionalSignatureComponents` on the
Resource and from `AdditionalComponents` on the signer. Empty requests then
need no digest. Keep the explicit component if empty requests must also carry
a signed digest: the signer computes the SHA-256 digest of zero bytes.
This applies to empty GETs and POSTs alike; a missing required component is
refused before your handler runs.

If you set a positive `http.Request.ContentLength`, it must match the actual
body size. Signing refuses a mismatch before attaching proof headers and
leaves the body readable. Zero or `-1` with a nonempty body remains supported.
Signing also refuses a positive length when the body is `nil` or `http.NoBody`.

[Resource tests](resource/body_coverage_test.go)
refuse added, changed and removed content, and changed media types, before
policy in all four token modes. [The example tests](example/verifyagent/main_test.go)
also exercise the explicit empty-body requirement and a valid POST.

Signed bodies are limited to 1 MiB by default. Set the Resource's
`MaxSignedBodyBytes` and the signer's `SignOptions.MaxBodyBytes` for your
service's limit. An oversized signed body currently returns `401 invalid_input`;
discovery does not advertise the limit. `agent.Config.MaxSignedBodyBytes`
sets the client limit. Streaming digest trailers are not implemented.

This is a stricter library default, permitted by the draft's Resource component
negotiation, rather than a universal protocol requirement. Callers that previously
sent unsigned Resource bodies must now cover the digest and any Content-Type.
Unconditional advertised components still apply to empty requests too.
See the [recorded interpretation](INTERPRETATIONS.md#nonempty-request-content-is-covered-by-default).

## Add revocation and application policy

Set `AgentIdentityConfig.AgentTokenRevocations` to a
`resource.AgentTokenRevocationStore`. For tests and examples,
`testutil.NewAgentTokenRevocationStore()` supplies an in-memory implementation
that passes the [public store contract](testutil/stores_test.go).
It retains markers for the store's lifetime, without cleanup or restart
persistence. Production stores must preserve revocations across restarts;
[the revocation example](example/revocation) shows the signed AP request.

The handler serves `GET /.well-known/aauth-resource.json` and advertises its
required signature components. Protected application routes require a proof
for HEAD and OPTIONS too. Configure browser preflight outside this handler
if needed.
Signatures can be replayed within their freshness window: write operations
need application idempotency. A stale proof returns `invalid_signature`;
a proof too far ahead returns `clock_skew`, as the pinned draft requires
([tests](signaturekey/clock_skew_external_test.go)).

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

## Plan AP signing-key rotation

`agentprovider.Server` publishes one signing key. Replacing that key can make
unexpired Agent tokens unverifiable after a verifier refreshes its JWKS cache.
The HTTP resolver supports multiple published keys and selects the token
header's `kid`; it does not try every key. For an overlap window, your host
must publish both old and new public keys at the discovered `jwks_uri`, retaining
the old key for tokens you still intend to accept. Automatic publication and
retirement are the **AP-KEY-ROLLOVER** gap in [CONFORMANCE.md](CONFORMANCE.md).
The [rotation test](integration/agentprovider_rotation_test.go) demonstrates
single-key replacement, cached verification, a host-published overlap set and
retirement after refresh.

## Compose authorization features

The table below collects the current composition limits. Support for two
features separately does not establish support for their combination; the
linked tests identify the combinations that execute. Full R3 compliance
remains the named **R3-FULL-COMPLIANCE** gap in
[CONFORMANCE.md](CONFORMANCE.md#companion-specifications).

A single Resource can serve free and priced routes. Set
`BudgetConfig.Metered` to select priced routes; `nil` requires a Budget on
every protected route. `Cost` runs only for metered calls. Free routes accept
Core Auth tokens; when given a Budget token, they report zero cost and its
current remainder. [Route tests](resource/budget_routes_test.go) execute both
cases, exhausted grants, and refusal feedback. A failed meter can omit
feedback; an unmetered route still runs when its meter fails. Handle
`BudgetCallUncertainError` without automatically retrying. A response without
`AAuth-Budget` does not prove that a call was free. For an uncached `200` or
`403` without that field, `BeginBudgetCall` returns that error and assumes
the whole signed grant was spent
([tests](agent/budget_call_test.go)). Use a Core token with `Do` for routes
that do not support Budget feedback.

**Custom Budget stores must support zero-cost observations.**
`BudgetStore.Charge` must accept `Cost == 0` and return the current remainder
without increasing token or person consumption. It may establish the token's
grant/context binding; at exhaustion it may return `ErrBudgetExhausted` with
both result fields zero. This changes the behavioral contract even though the
Go interface is unchanged. Rerun
[`resource/storetest.RunBudget`](resource/storetest/budget.go) against your
adapter: it now checks zero-cost observations before spending, after spending,
and at exhaustion, alongside binding and concurrent-cap enforcement.

| Combination | Current boundary and executable evidence |
| --- | --- |
| Core + Budget, three or four parties | Immediate grants and replacement-grant step-up; [three-party](integration/budget_three_party_test.go) and [four-party](integration/budget_four_party_test.go) tests. |
| R3 class + Budget | Immediate grants; denied operations report zero cost. [Three-party](integration/r3_budget_three_party_test.go) and [four-party](integration/r3_direct_four_party_test.go) tests. |
| AS deferred approval/payment + R3, Budget or missions | Immediate compositions retain their existing support; a deferred result is refused. See [deferred federation](#continue-an-as-approval-or-payment-request). |
| AS deferred approval/payment + one-level sub-agent | Missionless Core waits for the parent; the grant binds the child. See [Delegate to a sub-agent](#delegate-to-a-sub-agent) and the [integration tests](integration/subagent_federated_deferred_test.go). |
| Direct R3 + deferred Core consent | Constructor refuses this configuration; [configuration test](personserver/r3_direct_test.go). |
| Budget + deferred Core consent | Immediate requests work, but selecting deferred consent for a Budget request returns `500 server_error`; [request-time limit test](personserver/budget_test.go). |
| Reactive `Client.Begin` + mission Person token | Refused before sending; use proactive authorization. [Input tests](agent/call_test.go). |
| One Agent identity + several Person Servers | Use an Agent token and `Client` for each PS; a client rejects tokens naming another PS. [Context tests](agent/client_test.go). |

When combining Budget with a consent policy, inspect `AuthorizationRequest.Budget`.
If it is non-nil, use the immediate `Authorize` policy to approve or deny the
offer; do not select deferred consent. Interactive Budget consent is not
implemented, and `AuthorizationInteraction` has no Budget offer to display.

Check the boolean from `MissionResult.PersonToken(resource)`. A false result
means the approval contains no token for that exact Resource identifier.
`PersonTokens()` returns a copy of all returned Resource-to-token mappings;
use its keys when reporting the available Resources. [Mission tests](agent/mission_test.go)
cover present and absent Resources and protect the retained mapping from mutation.

## Continue an AS approval or payment request

For missionless Core, top-level or parent-mediated for a
[sub-agent](#delegate-to-a-sub-agent), set `accessserver.Config.Deferred` with an
AS-owned `accessserver.DeferredAuthorizationStore`, and
`personserver.FederatedAuthorizationConfig.Deferred` with a separate
`personserver.FederatedAuthorizationStore`. An AS policy returns `Decision.Pending` while
approval or payment is needed; a normal decision grants access.

The limit applies to each request, not to the PS's overall configuration: a
PS with Missions, R3 and Budget enabled can still defer a separate missionless
Core request. A local refusal returns `500 server_error` with a safe explanation.
Use `errors.As` on the diagnostic cause to inspect
`*personserver.DeferredCompositionError` and its `Reason()`; this is distinct
from `502 as_unreachable` for an unavailable or unverifiable AS response.
Unsupported AS claims, interaction and clarification requirements use the same
local refusal, including when they arrive on a later poll. `AdvanceFederation`
retains that terminal result; diagnostics reports its reconstructed typed cause
when the Agent polls. Store adapters must preserve `FederatedResponse.RefusalReason`
with the terminal response.

The Agent uses `BeginExchange` and `PollExchange`, and `CancelExchange` to
close its PS wait; the PS sends a best-effort withdrawal to the AS too.
`PendingExchange.WaitReason()`
returns `awaiting_payment`, `awaiting_approval`, or empty when the PS supplies no
recognized hint. These optional `pending_reason` values are a library extension
for display, not permission to pay. Payment details stay with the PS. Respect
`PendingExchange.RetryAfter()`: the PS derives it from the remaining AS polling
wait, rounded up to seconds, and updates it after AS backoff.

There are two polling schedules. `PendingExchange.RetryAfter()` tells the Agent
when to poll the PS again; the host record's `NextPollAt` tells the PS when it
may poll the AS. The PS advertises at least one second to the Agent even when
the host's AS poll is already due. `PollExchange` does not sleep or reject an
early call locally: the application schedules it. Polling the PS never advances
the AS request.

A PS host calls `PendingFederatedAuthorizationReferences(ctx, limit)` to list
outstanding work, then `FederatedAuthorization` to load each record. The bounded
snapshot includes in-flight requests and excludes expired or terminal ones;
listing does not reserve work. Authenticate the operator and filter records by
owner before displaying them. Inspect the retained AS response, settle payment
through the indicated protocol, then call `AdvanceFederation` when `NextPollAt`
is due and `Advancing` is false. The library does not settle payments. Hosts cache
billing relationships per AS; the AS's host remembers which PS has established
billing.

[Run the payment example](example/federatedpayment) for a complete
`402 → 202 → 200` path using these APIs. Its payment state is simulated.
`Retry-After` is enforced on AS polls; Agent polling never advances the AS
exchange implicitly. An in-flight AS call whose completion cannot be stored
stays fenced until expiry, because its terminal result may already be consumed.
Observe store errors and pending records rather than retrying that call.
Concurrent direct AS polls may each run policy and sign before one store update
wins; only that winner publishes its result. Policy must not charge on a poll.

Federation pending URLs distinguish `410 unknown_request`,
`410 request_consumed` and `403 wrong_poller`. A competing nonterminal AS update
returns `409 request_conflict`. These are [library error-code extensions](INTERPRETATIONS.md#federation-pending-url-error-names-and-competing-polls);
explicit policy denial remains `403 denied`.

The supported challenge carrier is `WWW-Authenticate`, with optional opaque
body content. Claims, clarification, interaction forwarding and deferred
R3/Budget/mission combinations remain unsupported. The earliest
original credential expiry and configured lifetime bound both pending records.
Custom adapters should run `accessserver/storetest.RunDeferredAuthorization`
and `personserver/storetest.RunFederatedAuthorization`. Pending listing is optional:
implement `personserver.FederatedAuthorizationQueueStore` and also run
`personserver/storetest.RunFederatedAuthorizationQueue` to support the host queue
API. Existing adapters can continue exchanges without listing; the queue API
returns an error when the adapter does not support it.

A pending result is delivered once per continuation. The pinned draft provides
no Auth-token claim binding it to a particular exchange, so an AS can return the
same still-valid grant for equivalent exchanges. The PS checks the grant's
identity, key, scope, context and expiry, but keeps no cross-exchange grant-JTI
cache. See [the source reading](INTERPRETATIONS.md#federated-grants-have-no-exchange-identifier)
and [the executable limit](integration/federated_deferred_test.go).

## Delegate to a sub-agent

A **sub-agent** is a child Agent with its own key, whose Agent token names its
parent in `parent_agent`. The parent makes every Person Server request and
poll; the child holds the issued Person and Auth tokens and is the only one
that calls the Resource. From the repository root, run the complete hosted
child request, three-party grant, delayed four-party grant and revoked binding:

```sh
go run ./example/subagent
```

The [complete program](example/subagent/main.go) wires every role and its stores.
Its `logicalTransport` routes the configured HTTPS origins directly to handlers;
its `Admit` method allows key discovery only at those origins. It needs no DNS,
listener, certificates or external account. A real network deployment supplies
its own HTTPS transport and trusted discovery policy. To run the same program
from a separate module, use the [checkout installation](#versions-and-local-development).

The snippets below extract the service integration steps; a
`testutil` test compiles them against the public API from an external module
and exercises the hosted registry's first request, collisions and limit.

**Issue the child token.** Only the parent's own Agent Provider can issue it.
A provider you run issues it directly from the parent's current token:

```go
func issueChild(ctx context.Context, provider *agentprovider.Server, parentToken string, childKey jose.JWK) (string, error) {
	return provider.IssueSubagent(ctx, parentToken, agentprovider.SubagentTokenRequest{
		Discriminator: "search", PublicKey: childKey, Lifetime: 30 * time.Minute,
	})
}
```

The child's `sub` becomes the parent's local part plus `+search`; its `exp` is
capped at the parent's. A hosted provider mounts `SubagentHandler` instead, on
the same origin as its metadata and JWKS, which the parent uses to verify the
child. Its policy records each parent's live sub-agents, here at most three,
and picks a free discriminator when the suggestion is taken:

```go
type subagentRegistry struct {
	mu       sync.Mutex
	byParent map[string]map[string]bool
}

func mountSubagents(mux *http.ServeMux, provider *agentprovider.Server, registry *subagentRegistry) {
	mux.Handle("/", provider.Handler())
	mux.Handle("POST /subagent", provider.SubagentHandler(func(_ context.Context, request agentprovider.SubagentRequest) (agentprovider.SubagentDecision, error) {
		registry.mu.Lock()
		defer registry.mu.Unlock()
		if registry.byParent == nil {
			registry.byParent = make(map[string]map[string]bool)
		}
		live := registry.byParent[request.Parent.Subject]
		if len(live) >= 3 {
			return agentprovider.SubagentDecision{}, fmt.Errorf("%w: parent has three active children", agentprovider.ErrSubagentDenied)
		}
		discriminator := request.Discriminator
		for n := 1; discriminator == "" || live[discriminator]; n++ {
			discriminator = fmt.Sprintf("worker%d", n)
		}
		if live == nil {
			live = make(map[string]bool)
			registry.byParent[request.Parent.Subject] = live
		}
		live[discriminator] = true
		return agentprovider.SubagentDecision{Discriminator: discriminator, Lifetime: 30 * time.Minute}, nil
	}))
}
```

The handler refuses a request it could not issue, such as the parent's own
key or a malformed discriminator, before the policy sees it. The host removes
a registry entry when it retires that sub-agent.

`403 subagent_denied` is deliberately generic: it can mean the host's quota or
another issuance policy refused the request, or that a child tried to create a
grandchild. Wrap `agentprovider.ErrSubagentDenied` with a host-local reason as
above and wrap `provider.SubagentHandler(...)` directly with
[`diagnostics.Handler`](#diagnose-a-refused-request) to observe that cause.
Select safe diagnostic fields for operators; the policy reason is not added to
the public response.

The parent then requests the token with its own signed request. The helper
sends only to the parent's provider origin and verifies the returned child:

```go
func requestChild(ctx context.Context, parent *agent.Client, childKey jose.JWK) (string, error) {
	return parent.RequestSubagentToken(ctx, agent.SubagentTokenRequest{
		Endpoint: "https://agents.example/subagent", PublicKey: childKey, Discriminator: "search",
	})
}
```

**Authorize through the parent.** The parent asks for a Person token bound to
the child. The child presents it to the Resource, and the parent exchanges the
child's Resource token. With four-party federation the exchange may wait for
AS approval or payment. Return the whole exchange result so the caller can
retain its pending continuation instead of losing it when no token is ready:

```go
func beginChildAuthorization(ctx context.Context, parent, child *agent.Client, childToken string, request *http.Request) (agent.ExchangeResult, error) {
	person, err := parent.PersonToken(ctx, agent.PersonTokenRequest{
		PersonServer: "https://person.example", Resource: "https://orders.example", SubagentToken: childToken,
	})
	if err != nil {
		return agent.ExchangeResult{}, err
	}
	personToken, ok := person.Token()
	if !ok {
		return agent.ExchangeResult{}, errors.New("the Person Server asked for interaction")
	}
	call, err := child.Begin(ctx, agent.InitialCall{Request: request, PersonToken: personToken})
	if err != nil {
		return agent.ExchangeResult{}, err
	}
	required, ok := call.AuthorizationRequired()
	if !ok {
		if response, ok := call.Response(); ok {
			response.Body.Close()
		}
		return agent.ExchangeResult{}, errors.New("the Resource did not ask for authorization")
	}
	return parent.BeginExchange(ctx, agent.ExchangeRequest{
		PersonServer: "https://person.example", ResourceToken: required.ResourceToken,
		PresentedToken: personToken, SubagentToken: childToken,
	})
}
```

This helper covers the immediate Person-token path; a service that supports
Person interaction must retain and handle that result too. For the exchange,
check `Token()`, `Failure()`, `Response()` and `Pending()` as documented on
[`agent.ExchangeResult`](agent/exchange_interaction.go). Close any returned HTTP
response body. Keep the latest pending value when scheduling another poll.

**Advance a delayed grant.** Scene 2 in the complete program shows both sides
of the wait. In a service, the steps have distinct owners:

1. The parent retains the `PendingExchange` from `BeginExchange`. It schedules
   `parent.PollExchange(ctx, pending)` using `pending.RetryAfter()` and paces
   repeated polls even if the interval is zero.
2. The authenticated PS host lists `PendingFederatedAuthorizationReferences`
   and loads each record with `FederatedAuthorization`. Filter the queue by
   owner before displaying it; listing neither reserves nor approves work.
3. The AS host records the person's approval or settled payment in its own
   application state. Its `Authorize` policy returns `Decision.Pending` until
   that state permits a normal grant. The example simulates approval with
   `approved.Store(true)`; that is not a public approval endpoint.
4. The PS host calls `AdvanceFederation(ctx, reference)` when `NextPollAt` is
   due and `Advancing` is false. This performs the AS poll and retains its
   result. Handle the method's error; an Agent poll cannot perform this step.
5. The parent's next poll obtains the result. Only the child uses the delivered
   Auth token at the Resource. The in-process example advances a due AS request
   and polls immediately under its fixed clock; a real caller still respects
   the Agent retry hint.

For an operator's view, `record.Agent` identifies the parent. Verify the retained
`record.AgentToken` with `aauth.VerifyAgentToken` at the current protocol time,
then pass those fresh parent claims and `record.SubagentToken` to
`aauth.VerifySubagentToken` to obtain the child's `Subject` and `ParentAgent`.
Verify `record.ResourceToken` with `aauth.VerifyResourceToken` to display its
`Scope` string as the requested scope. These helpers use your trusted key
resolver and clock. Show verification failures as unavailable details; do not
decode an unverified JWT for a trusted approval label or log the raw tokens.
This display does not authorize a grant; the normal role checks and host policy
still apply when advancing and delivering it.

The child alone signs the protected call, with `child.Do(ctx, agent.Call{...})`.
The parent cannot use the child's token: it is bound to the child's key. A
child's client refuses Person Server calls locally with
`agent.ErrSubagentPersonServerCall`; a child that signs its own request anyway
gets `400 invalid_agent_token` on PS Person-token and PS-hosted consent routes.
A child polling its parent's **federated** pending URL gets `403 wrong_poller`;
PS-hosted consent and Person-token pending routes instead reject it with
`400 invalid_agent_token`. `CancelExchange` on the parent closes the PS's
federated continuation and sends a best-effort withdrawal to the AS. A successful
PS cancellation does not confirm AS withdrawal; if the AS cannot be reached,
its pending request may remain until expiry.

**Revoke the parent's binding.** Configure an Agent-binding store on the
Person Server, then call `RevokeAgentBinding` from an authenticated
administrator action:

```go
func revokeParent(ctx context.Context, people *personserver.Server) error {
	return people.RevokeAgentBinding(ctx, personserver.AgentBinding{
		AgentProvider: "https://agents.example", Agent: "aauth:planner@agents.example",
	})
}
```

Set `AgentBindingRevocations` in `PSAuthorizationConfig` or
`FederatedAuthorizationConfig` (for example `testutil.NewAgentBindingRevocationStore()`
in tests), and run `personserver/storetest.RunAgentBindingRevocation` against a
custom store. While the binding is revoked, new Person tokens and missions for
the parent or any child are `403 person_token_denied`, token requests and
federated or consent waits are `400 revoked_presented_token`, Person-token
waits are `403 person_token_denied`, and chained calls are
`400 revoked_upstream_token`. Each refusal's `detail` names the revoked
binding, so a caller can tell it from a denial; a refused wait is ended, and
its pending URL answers `410` afterwards. Delivered grants are not revoked at
Resources, and the child Agent token remains valid until its normal expiry.
The Agent Provider still issues
sub-agent tokens, so a full cut-off also needs Agent Provider action and short
Auth-token lifetimes.

To bind the Agent to a person again, call `ReestablishAgentBinding` after your
`BindPerson` policy names the new person. Requests made after it are admitted;
every wait and presented token from before it stays refused, so no waiting
period is needed. Keep the store entries: deleting one re-admits whatever the
revoked binding authorized that has not expired.

An AS-issued Auth token cannot prove which binding authorized it using the
AS's clock. After replacement, obtain a fresh PS Person token for each new
authorization or step-up instead of presenting an AS Auth token. PS token
timestamps use whole seconds, so a fresh token's issuance second must be
strictly later than the replacement instant. Distinct host binding changes
use strictly increasing times; a stale replacement returns
`personserver.ErrAgentBindingStale` and leaves the revocation in force.
The Server convenience methods each begin a new host action. After an
indeterminate store error, inspect retained state; an exact retry through the
store uses the original caller-retained timestamp. Revocation checks and
issuance stores are separate interfaces, so hosts needing an atomic cutoff
against concurrent issuance must coordinate their administrative and issuance
operations. Already delivered credentials expire normally.

Policy sees both identities: `PersonTokenRequest.Agent` and
`AuthorizationRequest.Agent` name the parent whose consent applies;
`Subagent` names the child, with its own Agent Provider claims in
`SubagentAdditionalClaims`. The AS receives both as `AuthorizationRequest.Agent`
and `Subagent`. Limits: one level only, missionless only for AS waits, no
sub-agent call chaining, and no cascade from an Agent-token revocation to the
child's credentials. See [CONFORMANCE.md](CONFORMANCE.md) and
[the interpretations](INTERPRETATIONS.md#a-revoked-agent-person-binding-ends-issuance-and-pending-delivery).

## Chain a call through an Access Server

A Resource that calls another Resource for its caller acts as its own Agent
Provider and Agent (the intermediary). When the downstream Resource has an
Access Server, give the four-party Person Server a chaining policy:

```go
personserver.FederatedAuthorizationConfig{
	// ...
	CallChaining: &personserver.FederatedCallChainingConfig{
		BindPerson: mapUpstreamPersonToDownstreamPerson,
		Consent:    decideDownstreamRequest,
	},
}
```

The intermediary passes the person token its caller presented as
`UpstreamToken` in `PersonTokenRequest`, `AuthorizeRequest`,
`ExchangeRequest` and `Call`. The Person Server verifies it, calls
`BindPerson` for a new directed person and `Consent` for the downstream
request, and posts the exact `upstream_token` with the intermediary's Agent
token to the Access Server. The Access Server verifies it again: `typ`, an
`aud` equal to the intermediary's Agent-token `iss`, and a person token issued
by, or an auth token naming, the Person Server that signed. Its policy sees the
token in `AuthorizationRequest.UpstreamPerson` or `Upstream`, and the
intermediary in `Agent`. The auth token it issues has the downstream `sub` and
expires no later than the upstream token, and so does any wait for it. A bad
token is `400 invalid_upstream_token`, an expired one `expired_upstream_token`.

Limits: the four-party Person Server accepts only person tokens it issued as
upstream tokens, because it keeps no record of auth tokens an Access Server
issued. It refuses chained R3 and Budget requests, and a `202` or `402` from
the Access Server for a chained request is `500 server_error`.

## Deliver events to an Agent

AAuth Events lets a Resource notify an Agent that has no public URL: the
Resource posts to the Agent Provider (AP), which holds the event for the Agent.
[`example/events`](example/events) runs the whole path in one process.

**Agent Provider.** Set `agentprovider.Config.Events` to publish
`event_endpoint` (an HTTPS URL) in `/.well-known/aauth-agent.json` and to serve
the inbox there. `Server.IssueSubscribeToken` retains the subscription and
then returns the token. The inbox verifies each delivery and answers as Events
requires: `401` with `Signature-Error` for a token or proof failure, including
a body that does not match the token's `body_s256`; `403` for a Resource
other than the subscribed one; `404` for an unknown, inactive, or exhausted
subscription; and `202` only after your `EventInboxStore` retains the exact
token and body. Check your store with `agentprovider/storetest.RunEventInbox`.
Your own transport then hands the retained token and body bytes to the Agent
unchanged; Events leaves that mechanism to you.

**Resource.** `resource.NewEventService` returns the service, `eventService`
below, that serves subscription registration and prepares and sends events:

```go
prepared, err := eventService.PrepareEvent(ctx, resource.EventInput{
	AgentProvider: subscription.AgentProvider, EventID: subscription.EventID,
	ContentType: "application/json", Payload: body, Lifetime: 5 * time.Minute,
})
if err != nil {
	return err
}
result, err := eventService.DeliverEvent(ctx, prepared)
```

The Event token's `eid` and `aud` come from the registration, and a nonempty
`Payload` sets `body_s256`. `DeliverEvent` resolves the AP's current
`event_endpoint`, admits it through `AdmitEventEndpoint`, and reports
`RemainingUses` for a bounded subscription. To publish your AsyncAPI document,
set `EventServiceConfig.AsyncAPIDocument` and mount `AsyncAPIHandler`; the
service refuses a document that does not declare the `aauth_subscribe`
security scheme (`type: http`, `scheme: aauth-subscribe`).
`events.ValidateAsyncAPIDocument` applies the same check to a document you
serve yourself.

For a protected channel, call `IssueProtectedSubscriptionTicket` while serving
a request you verified with a person token or auth token, and pass that
token's key:

```go
principal, _ := resource.AuthPrincipalFromContext(request.Context())
ticket, err := eventService.IssueProtectedSubscriptionTicket(request.Context(), resource.ProtectedSubscriptionTicketRequest{
	ConfirmationKey: principal.Confirmation,
	Context:         []byte(`{"appointment":"a-17"}`),
	Lifetime:        2 * time.Minute,
})
```

The ticket records that key's JWK Thumbprint. Only a subscribe token whose
`cnf.jwk` has the same thumbprint can register at `ticket.URL`, once and
before it expires. Check your store with `resource/storetest.RunProtectedEvents`.

**Agent.** `Client.RegisterPublicSubscription` and
`Client.RegisterProtectedSubscription` present the subscribe token.
`Client.AcceptEvent` takes the token and body your AP transport delivered, and
refuses an expired token, an `aud` other than the Agent's own identifier, and a
body that does not match `body_s256`. Act on an event only after it returns
without error and with `Duplicate` false.

## Use in-memory stores in examples and tests

`testutil` provides concurrency-safe stores for examples, tests and local
development. Its constructors and returned interfaces are public module APIs,
with the same versioning expectations as the role packages. Pin a module
revision: the pre-v1 APIs may change as the drafts evolve. The stores retain
records for their lifetime and provide neither bounded retention nor restart
persistence.

There is no total record-count or memory cap. Long-running services must supply
role-specific adapters with a retention and capacity policy; restarting a
fixture discards its identities and decisions and is not a cleanup strategy.

| Constructor | State it owns |
| --- | --- |
| `NewMissionStore` | PS Person-token records (the `Tokens` store, with or without missions), mission lifecycle, proposals, permissions, audit and R3 issuance |
| `NewMissionInteractionQuestionStore` | The same mission state plus questions, sharing one transaction boundary |
| `NewMissionInteractionRelayStore` | The same mission state plus interaction relays, sharing one transaction boundary |
| `NewPermissionStore`, `NewInteractionQuestionStore`, `NewInteractionRelayStore` | Separate missionless PS stores |
| `NewEnrollmentStore`, `NewAgentTokenRevocationStore` | AP enrollment or Resource revocation, respectively |
| `NewDeferredAuthorizationStore` | PS consent and clarification, sharing one transaction boundary |
| `NewAccessAuthorizationStore`, `NewFederatedAuthorizationStore` | Separate AS request retention and PS federation continuation |
| `NewBudgetStore` | Resource fixed-price token consumption and person totals |
| `NewR3DocumentStore`, `NewR3IssuanceStore` | Resource documents or role-local issuance audit, respectively |
| `NewIssuedAuthTokenStore`, `NewAuthTokenStatusStore` | PS-issued Auth tokens or Resource revocation status, respectively |

The mission constructors expose their supported interfaces directly. Configure
mission features with the same store instance; separate instances do not share
state. The [mission](example/mission), [permission](example/permission),
[question](example/interactionquestion) and [relay](example/interactionrelay)
examples use these public constructors. An [external consumer test](testutil/external_examples_test.go)
copies and runs these examples and the [consent](example/psconsent),
[Budget](example/budget) and [revocation](example/revocation) examples outside
the library module.

Each constructor returns a separate store. Use one instance for each deciding
role; the fixtures do not combine PS consent with mission lifecycle transactions.
Declare consent-store fields as `personserver.DeferredAuthorizationStore`;
`testutil.NewDeferredAuthorizationStore` returns that interface. The returned
store also implements the optional `personserver.AuthorizationClarificationStore`
extension, which the Person Server discovers when configured with the store.

Durable adapters must satisfy the
[Resource](resource/storetest), [Access Server](accessserver/storetest), [Person Server](personserver/storetest)
and [Agent Provider](agentprovider/storetest) contracts and the
[R3 issuance contract](r3/storetest).
The public mission fixture exposes `LoadAuthToken` and `LoadR3Issuance` for
the observation callbacks required by `RunMission` and `RunMissionR3Issuance`.
Use the [public-constructor contract tests](testutil/mission_contracts_test.go)
as the wiring example; they also run from an external module.

`testutil.MissionStore` and its question/relay variants now include those two
read-only observers. Custom implementations of these test-helper interfaces
must add them. Production adapters should implement the role interfaces and
provide their own storetest observation callbacks; the role interfaces did
not gain these fixture methods.

## Find requests waiting for the person

Use `Server.PendingPermissionReferences(ctx, limit)` or
`Server.PendingInteractionQuestionReferences(ctx, limit)` to discover retained
work, including after Server recomposition. Limits are 1–1000; results belong
to this PS and are ordered by creation time, then reference. The public fixtures
support both lists; production adapters opt in through `PermissionQueueStore`
or `InteractionQuestionQueueStore` and should run the
[pending queue contracts](personserver/storetest/pending.go).

Authenticate the person in your application, then call `ResumePermission` or
`ResumeInteractionQuestion` for each reference before displaying or deciding
it. Lists span all people at this PS, and resume does not authenticate the viewer:
**filter each resumed request by owner before showing it or allowing a decision.**
Listing does not claim work. Expiry, another decision, or mission termination
can invalidate a reference; a terminated mission's request may remain listed
until its own deadline. The [permission](example/permission/main.go) and
[question](example/interactionquestion/main.go) examples execute this host flow
without extracting references from the Agent's poll URL. Mission proposals
have a separate [pending queue](personserver/mission_proposal_deferred_test.go).

## Point Agents at your metadata

An Agent that lands on your developer portal or API host may not know your
resource identifier yet. The `aauth-resource` link relation names your
metadata document from any response or page. Wrap the handlers that serve those
pages, and the Resource itself if you like:

```go
portal.Handle("/docs/", server.WithResourceLink(docs))
api := server.WithResourceLink(server.Handler())
```

Each response then carries
`Link: <https://api.example/.well-known/aauth-resource.json>; rel="aauth-resource"`.
In an HTML template, put `aauth.ResourceLinkElement(issuer)` in the `head` of
the page at your `documentation_uri`. `aauth.AddResourceLinks` adds the field
to any header, with one link for each resource a page describes. The link says
nothing about the response it rides on: a `401` still states its requirement in
`AAuth-Requirement`.

An Agent reads links with `agent.ResourceLinksFromResponse` and
`agent.ResourceLinksFromHTML`. Both keep only targets of the one admissible
form, a server identifier followed by `/.well-known/aauth-resource.json`, and
record where each link was found and how. Keep that record: a resource that a
third-party page introduced is not one the person named. Then fetch and verify
the document:

```go
links := agent.ResourceLinksFromHTML(pageURL, page)
linked, err := agent.ResolveResourceLink(ctx, keyResolver, links[0])
// linked.Resource is the verified resource identifier.
```

`ResolveResourceLink` refuses any other target form before fetching. A
`signaturekey.HTTPKeyResolver` fetches with your `Admit` callback, its
destination checks and size bound, and without following redirects. The
document's `issuer` must equal the target minus the well-known suffix, or the
result is `issuer_missing` or `issuer_mismatch`. A link authorizes nothing and
is never used to find keys: the person still approves the resource at the
person token endpoint, and verifiers discover keys from `iss` and `dwk`. The
HTML scan treats the page as untrusted input, reads at most 1 MiB, and uses
only absolute targets.

## Verify a signed request after a delay

A role handler verifies each request as it arrives, within the signature
window. A batch pipeline or a store-and-forward hop first sees a signed
request later. Set `VerifyOptions.MaxDelay` to the delay you accept; the signed
`created` is then the anchor, and any token presented with the request must
have been valid at that instant:

```go
prepared, err := signaturekey.PrepareRequest(stored, clock, signaturekey.VerifyOptions{
	MaxDelay: 24 * time.Hour,
})
// handle err
compact, _ := prepared.Credential().JWT()
claims, err := aauth.VerifyAgentToken(ctx, compact, keys, aauth.ClockFunc(prepared.ValidAt))
// handle err, then prepared.CheckIssuedAt and prepared.Verify(claims.Confirmation.JWK)
```

`created` may be up to `MaxDelay` old, but not further ahead of your clock than
the signature window (`clock_skew`). A signature whose `expires` has passed is
refused whatever the delay. Your key resolver must still hold the issuer keys
that were current at `created`.

To refuse a request presented twice, keep one `signaturekey.ReplayCache` per
verifier and call `cache.Check(proof)` after verifying. It keys each entry by
the signing key's thumbprint, `created`, method, authority and path, and holds
it until `created` plus `proof.MaxAge()`: the signature window online, or the
whole delay a delayed verifier accepts. A repeat is `invalid_signature`. A full
cache returns `ErrReplayCacheFull` rather than forget an entry early. Two
requests from one key to the same path in the same second share a tuple, so
only use the cache where that cannot happen legitimately.

## Verify other Signature-Key schemes

The role handlers accept the Signature-Key schemes their protocol step needs,
with Ed25519 keys, and answer any other scheme with `unsupported_scheme`. An
endpoint of your own can use the `signaturekey` package directly. Name the
schemes and algorithms it accepts, then finish with the verifier for the
selected scheme:

```go
func verifyCaller(ctx context.Context, request *http.Request, clock signaturekey.Clock,
	keys signaturekey.JWKSKeyResolver, chain func(x5u string) (signaturekey.X509VerifyOptions, error),
) (signaturekey.VerifiedRequest, error) {
	prepared, err := signaturekey.PrepareRequest(request, clock, signaturekey.VerifyOptions{
		AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeHWK, signaturekey.SchemeJWKS, signaturekey.SchemeX509},
		AcceptedAlgorithms: []string{jose.Ed25519Algorithm, jose.ES256Algorithm},
	})
	if err != nil {
		return signaturekey.VerifiedRequest{}, err
	}
	credential := prepared.Credential()
	switch credential.Scheme() {
	case signaturekey.SchemeHWK:
		key, _ := credential.InlineJWK()
		return prepared.Verify(key)
	case signaturekey.SchemeJWKS:
		return prepared.VerifyJWKS(ctx, keys)
	default:
		x5u, _, _ := credential.X509()
		options, err := chain(x5u)
		if err != nil {
			return signaturekey.VerifiedRequest{}, err
		}
		proof, _, err := prepared.VerifyX509(options)
		return proof, err
	}
}
```

A protocol refusal is a `*signaturekey.Error`. Its `Code` goes in `Signature-Error`,
and `AcceptedSchemes` or `AcceptedAlgorithms` in `Accept-Signature-Scheme` or
`Accept-Signature-Alg` (see `FormatError`, `FormatAcceptSchemes` and
`FormatAcceptAlgorithms`).

**Algorithms.** `AcceptedAlgorithms` defaults to Ed25519. An `hwk` or `x509`
key may also use `ES256`, `ES384`, `RS256` or `PS256` when you list it. Every
key must carry a fully specified `alg`, and `kty` and `crv` must agree with it.
A key whose `alg` you did not list is `unsupported_algorithm`, and the error
names exactly your list. JWT-carried and discovered keys, and AAuth tokens,
remain Ed25519. A client signs with another algorithm through
`jose.NewSigningKeyForAlgorithm` and `signaturekey.SignHWKRequest`.

**Direct JWKS.** In `jwks`, the `url` is both the signer's identity and the
location of its keys. It is compared byte for byte and never normalized, and
`proof.Signer()` returns it unchanged. `signaturekey.HTTPKeyResolver`
implements `JWKSKeyResolver`: it admits the URL through your `Admit` callback
and fetches it under the same destination checks, cache and one-minute refresh
floor as `jwks_uri`. `StaticJWKSResolver` is an exact in-memory alternative.

**X.509.** This package does not fetch `x5u`. Your host fetches that exact
URL after its own egress checks and passes the PEM chain, the trust anchors
it accepts, and current CRLs for the end entity and each intermediate. The
chain and revocation are always checked before the `x5t` thumbprint and the
signature. A revoked certificate, or one that no current CRL covers, is
`invalid_key`. The end-entity key selects Ed25519, ES256 or ES384. An RSA
certificate names neither padding nor hash, so it is `unsupported_algorithm`.
OCSP, delta CRLs and partitioned CRLs are not supported.

**Several signatures.** `signaturekey.SignRequests` signs one request with
several labeled signatures. It writes every `Signature-Key` member before it
signs, and each signature covers `signature-key`. A verifier selects one label
with `VerifyOptions.SignatureLabel`.

### Cache an assertion

A caller that presents a `jwt` or `jkt-jwt` assertion with the `cache` signal
asks the verifier to issue a short **cache identifier** that later requests
present instead. Caching is optional: an endpoint that does not accept
`cached` answers it with `unsupported_scheme`, and the caller resends the full
assertion.

To cache, create one `signaturekey.AssertionCache` per verifier with a 32-byte
secret shared by your verifier fleet. After you verify a request that asked to
be cached, issue an identifier and return it in `Signature-Key-Cache`:

```go
grant, issued, err := cache.Issue(proof)
if err == nil && issued {
	if field, err := signaturekey.FormatCacheGrants(grant); err == nil {
		response.Header().Set("Signature-Key-Cache", field)
	}
}
```

Accept `signaturekey.SchemeCached` on later requests and verify them with
`prepared.VerifyCached(cache)`. An identifier the cache cannot resolve is
`cache_miss`; answer `401` so the caller resends the assertion in full. A
resolved identifier still needs a valid HTTP signature from the assertion's
confirmation key. An assertion that has expired is `expired_jwt`, not
`cache_miss`. Then validate the returned `CachedAssertion` as you would the
assertion presented in full: on the issuing node, `Compact` returns its exact
bytes. `Issue` never caches a `self-jwt`, an assertion without `jti`, or one
with more than 24 hours left to live. An identifier's `expires` never outlives
the assertion.

On the client, wrap the full credential in `signaturekey.NewCachingCredential`.
Present `Credential()` on each request, and pass each response to
`HandleResponse`. The client presents the cached identifier only after a
verifier issued it. After a `cache_miss` it presents the full assertion again,
whatever the advisory `expires` said. `signaturekey.SelectScheme` picks a
scheme from a server's `Accept-Signature-Scheme`. It skips `cached` until an
identifier has been issued.

## Diagnose a refused request

Wrap the role handler directly with `diagnostics.Handler` to observe the original
cause of an AAuth problem response:

```go
handler := diagnostics.Handler(service.Handler(), func(ctx context.Context, p diagnostics.Problem) {
    // Use errors.Is/As on p.Cause; retain only selected, redacted log fields.
    logger.LogAttrs(ctx, slog.LevelWarn, "AAuth request refused",
        slog.Int("status", p.Status), slog.String("code", p.Code))
})
```

The [runnable example](diagnostics/example_test.go) receives a local cause while
the caller receives the protocol refusal. The callback runs synchronously after
serialization and must handle concurrent requests. Causes can contain private
host data; nothing logs them automatically. The wrapper preserves standard HTTP
writer capabilities and `http.ResponseController`; custom writer interfaces are
not preserved. It observes problems written by the role serializer, including
`mission_terminated` with its typed cause. It does not observe:

- `AAuth-Requirement` challenges, including Budget step-up, or successful polls;
- application responses and router-generated errors;
- plain-text HTTP 421 refusals for a foreign authority from either Resource
  handler; observe these through your outer HTTP access logger;
- retained held-invocation responses replayed by a Resource, including its
  stored `server_error` fallback (the original cause is not retained);
- errors returned directly from non-HTTP methods, including `AdvanceFederation`;
- retained federation results delivered by a PS, except local
  `DeferredCompositionError` refusals, whose typed reason is reconstructed on
  delivery. Other asynchronous causes are not retained; inspect the continuation
  record and method error as well as HTTP access logs.

## Versions and local development

For in-process development, use `https://resource.example` as in the runnable
example; no DNS or listener is needed. With a local TLS listener, keep that
logical request host and route its connection to loopback through your test
transport. Changing `Issuer` alone does not make a request to
`127.0.0.1:8080` match it. The [local walkthrough](walkthrough/local) shows
separate TLS processes and certificates at its declared module pin.

**HTTP 421 behind a reverse proxy:** every request through
`resource.Server.Handler` or `resource.ResourceManagedServer.Handler`, including
discovery, must match the configured `Issuer` authority. For a service reached
as `https://resource.example`, set
`Issuer` to that identifier and configure the proxy to forward
`Host: resource.example`, even if its upstream connection goes to
`127.0.0.1:8080`. Preserve the signed path and query too. `Forwarded` and
`X-Forwarded-Host` do not override the check.

Changing `Issuer` to a backend hostname alone cannot repair a Host rewrite
after signing: the request proof also binds the caller's original authority.
If you expose a different Resource identity, configure it consistently in
the Resource, discovery, callers and Auth-token audiences; callers must sign
that target. [Authority tests](resource/authority_test.go) exercise the
receiving-host and signed-request checks; [session tests](resource/session_authority_test.go)
cover initial authorization, session use, discovery and pending routes.

`go get gitlab.com/sidecat-dev/aauth-go` records a published version in your
module. Review and commit `go.mod` and `go.sum`; these editor drafts and APIs
are still evolving. The standalone `walkthrough/` modules deliberately pin
published pseudo-versions. Their tests exercise those versions, not this
checkout.

To try the current checkout in a separate module, start in the `aauth-go`
repository root. Capture its absolute path before changing directories. This
creates a temporary consumer and copies the complete sub-agent example into it:

```sh
aauth_checkout="$(pwd -P)"
aauth_consumer="$(mktemp -d "${TMPDIR:-/tmp}/aauth-consumer.XXXXXX")"
cd "$aauth_consumer"
go mod init example.com/aauth-consumer
go mod edit -require=gitlab.com/sidecat-dev/aauth-go@v0.0.0
go mod edit "-replace=gitlab.com/sidecat-dev/aauth-go=$aauth_checkout"
cp "$aauth_checkout/example/subagent/main.go" .
go mod tidy
go list -m gitlab.com/sidecat-dev/aauth-go
go run .
```

The `go list -m` output must show `=>` followed by your absolute checkout path.
The run prints the issued child, successful `records.read` and `orders.read`
calls, the approval wait and the final `person_token_denied` refusal. The
placeholder `v0.0.0` is satisfied by the local replacement; it is not a published
release. For an existing application, apply the same absolute replacement to
its module and run `go mod tidy` after adding imports. A replacement does not
publish or pin the checkout's contents, so record the checkout commit when
sharing results. Remove the replacement and select a published version before
distributing a module intended to work without your local checkout.
