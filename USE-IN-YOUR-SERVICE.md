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
| AS deferred approval/payment + R3, Budget, delegation or missions | Immediate compositions retain their existing support; a deferred result is refused. See [deferred federation](#continue-an-as-approval-or-payment-request). |
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

For top-level missionless Core, set `accessserver.Config.Deferred` with an
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

The Agent uses `BeginExchange` and `PollExchange`. `PendingExchange.WaitReason()`
returns `awaiting_payment`, `awaiting_approval`, or empty when the PS supplies no
recognized hint. These optional `pending_reason` values are a library extension
for display, not permission to pay. Payment details stay with the PS. Respect
`PendingExchange.RetryAfter()`: the PS derives it from the remaining AS polling
wait, rounded up to seconds, and updates it after AS backoff.

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
R3/Budget/delegated/mission combinations remain unsupported. The earliest
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
| `NewMissionStore` | PS mission lifecycle, proposals, permissions, audit and R3 issuance |
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
[Resource](resource/storetest), [Access Server](accessserver/storetest) and [Person Server](personserver/storetest)
contracts and the [R3 issuance contract](r3/storetest).
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

To try this checkout from a consumer module placed beside it:

```sh
go mod edit -replace=gitlab.com/sidecat-dev/aauth-go=../aauth-go
go mod tidy
```
