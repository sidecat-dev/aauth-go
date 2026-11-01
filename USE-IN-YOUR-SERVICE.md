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

A request with a body must sign it; a request without one needs no digest.
Leave `AdditionalSignatureComponents` unset unless you need more: see
[Protect request bodies](#protect-request-bodies).

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
claim selects that well-known document.

For network discovery, use `signaturekey.NewHTTPKeyResolver`. `Client` is the
HTTP client it fetches with and `Clock` the protocol time. `Admit` sees each
metadata or JWKS URL before it is fetched and returns an error to refuse it:
admit only the issuers you trust, because a token names its own issuer. The
resolver also checks each connection itself. It resolves the host, refuses
private, loopback and link-local addresses, connects only to the address it
checked, and never follows a redirect. To do that it dials through a copy of
your client's `*http.Transport`, so it refuses, at construction, a client
whose transport is another type or has a proxy or a dialer other than
`DialContext`. Two settings change this:

- For issuers at private addresses on your own network, `AllowDestination`
  admits the addresses it returns true for, and `LookupAddresses` resolves
  hosts the system resolver does not know.
- For a transport that applies its own destination controls or makes no
  connection, such as an in-memory test transport or a client that reaches
  only your own loopback listeners, set `TransportEnforcesEgress: true`. The
  resolver then uses the client unchanged.

[Fetch issuer keys](docs/roles/resource.md#fetch-issuer-keys) compares the
cases, and [Get started](docs/getting-started.md) runs the last one over
loopback TLS.

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

The handler above uses this default. To require `content-digest` on *every*
request, including empty ones, list it in `AdditionalSignatureComponents`, as
the example's `digestEverywhereResource` does. Its caller supplies that
unconditional component:

```go
func signAgentRequest(request *http.Request, key jose.SigningKey, token string, clock aauth.Clock) error {
	return signaturekey.SignJWTRequestWithOptions(request, key, token, clock, signaturekey.SignOptions{
		AdditionalComponents: []string{"content-digest"},
	})
}
```

The signer preserves the body for transport and computes the SHA-256 digest
of zero bytes for an empty request. The requirement applies to empty GETs and
POSTs alike; a missing required component is refused before your handler runs.

The Resource lists such components in its metadata, and they apply to every
request. `agent.Client.CallAsAgent` reads the metadata and covers them. An
Agent that signs without reading the metadata is refused with `401` and
`Signature-Error: invalid_input`, naming the component in `required_input`.
aauth-rust's `Agent::sign`, for example, covers an extra component only when
it is given the list with `with_additional_signature_components`. Use the
default unless your service needs a digest on empty requests.

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

## Revoke person and resource tokens

Each role records a revocation under `(iss, jti)`, where `iss` is the server
that signed the revocation request, before it calls anyone downstream.
`testutil.NewTokenRevocationStore()` is an in-memory store that satisfies every
role's revocation store interface. Production stores keep each marker at least
until the revoked token's `exp` plus clock skew, and survive restarts.

A Person Server revokes a person token it issued with `RevokePersonToken`. It
revokes the token at the Resource named in its `aud` and at every Access Server
it was presented to, and from then on refuses it as a `presented_token` with
`revoked_presented_token`:

```go
people, err := personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
	// ...
	TokenRevocation: &personserver.TokenRevocationConfig{
		Revocations: revocations, HTTPClient: client, Admit: admit,
	},
})

result, err := people.RevokePersonToken(ctx, personTokenJTI)
for _, attempt := range result.Attempts {
	// attempt.Recorded(), attempt.Pending or attempt.Error per recipient
}
if result.Pending() {
	// Call RevokePersonToken again after result.RetryAfter().
}
```

Each call makes one attempt at each recipient that has not recorded the
revocation, and waits at most `Hold` (20 seconds by default). A recipient that
answers `202` or `429 rate_limited` is reported pending, and a call after its
`RetryAfter` polls its pending URL with a signed `GET`, or sends the revocation
again. A failed recipient is `revocation_unavailable` or
`revocation_unsupported` and is attempted again on the next call. Repeating the
call is safe. A person token passed to an Access Server as `upstream_token`
counts as presented to it, so it is revoked there too and the Access Server
refuses it with `revoked_upstream_token`.

Two optional store extensions let the cascade reach what was obtained with the
person token. When the issued auth-token store implements
`personserver.AuthTokenLineageStore`, every auth token obtained with it,
step-ups included, is recorded as revoked, so the Person Server refuses it as a
presented or upstream token, and those the Person Server issued itself are
revoked at their Resources; an Access Server revokes its own. When `Tokens`
implements `personserver.ChainedPersonTokenStore`, the person tokens a
call-chaining intermediary obtained with any of these as `upstream_token` are
revoked the same way, hop by hop down the chain. `testutil.NewMissionStore` and
`testutil.NewIssuedAuthTokenStore` implement both.

An Agent Provider's revocation of an Agent token cascades the same way when the
Person Server has `AgentTokenRevocations`, `TokenRevocation` with `HTTPClient`
and `Admit`, and a `Tokens` store that implements
`personserver.AgentPersonTokenStore`. Every unexpired person token issued to
that Agent, under any of its Agent tokens, is revoked at its Resource, at each
Access Server it was presented to, and down its chains. The Person Server holds
the request for up to `Hold` and answers an empty `200` once each recipient has
a terminal outcome, or `202` with a pending URL under `/revoke/pending/`.
`agentprovider.RevocationClient` then returns
`*agentprovider.RevocationPendingError`; revoke again after its `RetryAfter`,
which records nothing new and continues the cascade.

An Access Server with `accessserver.Config.Revocation` serves `POST /revoke` and
advertises `revocation_endpoint`. It retains each auth token it issues in
`IssuedTokens`, with the token presented for it. When its Person Server revokes
a person token, it revokes every auth token issued against it, step-ups
included, at the Resource each names. It answers `200` with a `downstream`
report, or `202` with a pending URL that only the revoking Person Server may
poll. It refuses a revoked person token, upstream token or resource token in a
later token request, and ends a request waiting on one with `403 revoked`,
whose `detail` names the token.

A Resource withdraws a resource token with `RevokeResourceToken`. In
three-party access it revokes the token at the Person Server in its `aud`; in
four-party access at the Access Server and at its `ps`. Each recipient refuses
it with `revoked_resource_token` and ends a request waiting on it with
`revoked`:

```go
protected, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
	// ...
	AuthTokenStatuses: authTokens,
	Revocation: &resource.RevocationConfig{
		PersonTokens: revocations, HTTPClient: client, Admit: admit,
	},
})

result, err := protected.RevokeResourceToken(ctx, resource.ResourceTokenRevocation{
	JTI: jti, ExpiresAt: expiresAt, Audience: accessServer, PersonServer: personServer,
})
```

`PersonTokens` makes the Resource refuse a revoked person token with
`Signature-Error: error=revoked_jwt`, so it issues no resource token naming it.
`AuthTokenStatuses` on a four-party Resource accepts revocations from its Access
Server.

The Agent treats `revoked_resource_token` as terminal for that token.
`agent.Client` remembers the refused token and refuses to submit it again with
`*agent.RevokedResourceTokenError`, which matches `agent.ErrResourceTokenRevoked`.
Call the Resource again for a fresh one.

Every revocation endpoint accepts 600 requests a minute from one caller by
default and answers `429 rate_limited` with `Retry-After` beyond that; set
`Limits` to change it. A cascade that meets a recipient's limit is not lost:
that revocation stays pending until the `Retry-After` has passed. A store may return `aauth.ErrRevocationLimitReached` to
bound how many entries one issuer holds. An `exp` more than 24 hours ahead is
`invalid_request`. The [revocation cascade tests](integration/revocation_cascade_test.go)
run these paths through the real role handlers.

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

All Go snippets execute in [the complete example](example/verifyagent).
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
| AS deferred approval/payment + R3 or Budget | Immediate compositions retain their existing support; a deferred result is refused. Mission-bound Core requests can wait. See [deferred federation](#continue-an-as-approval-or-payment-request). |
| AS deferred approval/payment + one-level sub-agent | Missionless Core waits for the parent; the grant binds the child. See [Delegate to a sub-agent](#delegate-to-a-sub-agent) and the [integration tests](integration/subagent_federated_deferred_test.go). |
| Direct R3 + deferred Core consent | Constructor refuses this configuration; [configuration test](personserver/r3_direct_test.go). |
| Budget + deferred Core consent | The Person Server keeps the Resource token's offer while the person decides, and `ApproveAuthorizationInteraction` mints the Budget its decision grants, which must narrow the offer. A request that did not declare the `interaction` capability is `403 user_unreachable`. [`TestBudgetAuthorizationInteractionIsARequestTimeLimit`](personserver/budget_test.go). |
| Reactive `Client.Begin` + mission Person token | Refused before sending; use proactive authorization. [Input tests](agent/call_test.go). |
| One Agent identity + several Person Servers | Use an Agent token and `Client` for each PS; a client rejects tokens naming another PS. [Context tests](agent/client_test.go). |

When combining Budget with a consent policy, inspect `AuthorizationRequest.Budget`.
If it is non-nil, the Resource offered a Budget, and the decision must grant
one in the same unit and scale, no larger: in `AuthorizationDecision.Budget`,
returned from `Authorize` or passed to `ApproveAuthorizationInteraction` after
deferred consent. A decision that omits it or exceeds it is a host error: the
immediate request fails with `500 server_error`, and
`ApproveAuthorizationInteraction` returns the error.
`AuthorizationInteraction` does not expose the offer; to show it to the
person, keep it from the `AuthorizationRequest` that
`RequireAuthorizationInteraction` receives.

Check the boolean from `MissionResult.PersonToken(resource)`. A false result
means the approval contains no token for that exact Resource identifier.
`PersonTokens()` returns a copy of all returned Resource-to-token mappings;
use its keys when reporting the available Resources. [Mission tests](agent/mission_test.go)
cover present and absent Resources and protect the retained mapping from mutation.

## Organize R3 definitions and gate release

**Several internal definitions.** A Resource may keep its R3 authorization in
several definitions of its own, for example one per scope. List them in
`R3VocabularyConfig.InternalDefinitions`, each with its operations and display;
together they must cover every operation of the vocabulary's `Definition`. An
agent request whose operations fall under more than one definition still gets
one Resource token naming one document: its operations are exactly the
requested ones, and its display merges each involved definition's display with
`r3.MergeDisplays`. `DisplayForOperations`, when set, writes the display for
the combination instead, and is where to name an `account` in words the person
recognizes. The document's bytes are retained in your `R3DocumentStore` as for
any R3 document.

**Approve release rather than execution.** For a per-call operation with no
side effects, set `R3PerCallConfig.Release`:

```go
config.R3.PerCall.Release = &resource.R3ReleaseConfig{
	Eligible: func(ctx context.Context, call r3.Invocation) (bool, error) {
		return isReadOnlyQuery(call), nil
	},
	DescribeResult: func(ctx context.Context, ran resource.R3ReleaseRequest) (resource.R3ReleaseDescription, error) {
		return resource.R3ReleaseDescription{
			Parameters: queryParameters(ran.Invocation),
			Result:     json.RawMessage(`{"records":214,"contains":["compensation"]}`),
			Display:    releaseSummary, // "Release the result of a query over employee records"
			Detail:     "## Details\n214 rows.",
		}, nil
	},
}
```

It applies to a call the Resource holds under `202` (`HeldInvocations` and
`HoldAuthTokenRequest`). The Resource runs the held call at once under the
class Auth token, passes the response to `DescribeResult`, and publishes a
proposal with your `result` members and a display whose detail opens with
`r3.ReleaseAction`, the statement that the operation has run and that what is
approved is release of its result. The first poll with the per-call Auth token
receives the retained response; the call never runs again, and a result whose
release is never approved is never sent. Return true from `Eligible` only when
nothing outside the result changes when the call runs: not for a call that is
audited or billed, or that calls another party. The Resource itself never runs
first a route its Budget profile meters, or an operation annotated
`budget: true` unless it meters the release. Held stores must copy
`HeldR3PerCall.Release`; rerun `resource/storetest.RunHeldInvocation`.

**Meter the release.** When what an operation annotated `budget: true`
charges for is the result rather than running it, set `MeterRelease` and
state the cost in `DescribeResult`:

```go
config.R3.PerCall.Release.MeterRelease = true // needs config.Budget
// in DescribeResult, for an annotated operation:
cost, _ := budgets.NewValue(40, credits) // a declared denomination
description.Cost = &cost
```

The Resource needs its Budget profile, with `Metered` leaving the per-call
route unmetered so the class Auth token reaches the per-call challenge. An
unannotated operation's release states no `Cost`. The proposal's Resource
token offers exactly the cost as `budget`; the Person Server's
`FederatedBudgetConfig.Ceiling` and the Access Server's
`R3ProposalDecision.Budget` grant it on the per-call Auth token. The Agent's
`PollR3Call` checks that grant against the offer. The poll that presents the
per-call token draws the cost down once: the released response carries
`AAuth-Budget`, and a replay reports `remaining` without metering again. A
per-call token without a budget is `403`; one whose budget is below the cost
is `403` with `AAuth-Budget` stating `required`, and the result stays held for
a token that fits. A declined release meters nothing.

## Hold a Budget refusal

A four-party Resource with a Budget profile can answer a Budget refusal with
`202` instead of `401` and hold the call. Configure `HeldInvocations` with a
store that also implements `resource.HeldBudgetStore`, a Budget store that
implements `BudgetReserver`, and `HoldAuthTokenRequest`. The `202` carries the
same `AAuth-Requirement`, reason and fresh Resource token as the `401`, and
`AAuth-Budget` reports the refused token's `remaining` and `required` only.
Nothing is reserved against or metered to the refused token.

The agent obtains a new Auth token and polls the `Location`. On that poll the
Resource reserves the call's `Maximum` (or fixed `Cost`) against the poll's
token, runs the call, and commits; the handler may call `SettleBudget` as on a
direct call. A poll token whose remainder is too small gets another `202` with
`reason=insufficient-budget` and a fresh Resource token naming it, and the call
stays held at the same URL; the store's `Rechallenge` swaps the Resource token.
A repeated poll with the completing token is answered from the stored result,
metered once, with `AAuth-Budget` reporting that token's current remaining.
With a Budget profile, the Resource holds only Budget refusals: person-token
and R3 per-call challenges answer `401`, because their held completion would
run a metered route unmetered. A refused token that carries R3 claims is
answered `401`.

## Sign and verify Budget usage

A Resource whose `BudgetStore` implements `BudgetUsageStore` serves the
`usage_endpoint` and signs each answer with its own key, as AAuth Budgets
recommends: the signature covers `@status`, `content-type` and
`content-digest`, and binds the answer to the query with `@authority` and
`@path` under `req`. A Resource configured without a key ID answers unsigned.

A Person Server or Access Server asks with `budgets.PostUsageChecked`:

```go
result, err := budgets.PostUsageChecked(ctx, usageEndpoint, psKey, psIssuer,
	aauth.PersonDiscoveryDocument, clock, budgets.UsageRequest{Subject: sub},
	budgets.UsageSignatureCheck{Resource: resourceIssuer, KeyResolver: keys})
if err != nil {
	return err
}
if result.Signed {
	keepEvidence(result.ExactBody, result.Header)
}
```

A signature must verify under a key from the Resource's own metadata and for
this query; one that does not is refused. An unsigned answer is read and
reported with `Signed` false, because the draft recommends signing rather than
requiring it; set `RequireSignature` to refuse it. Keep `ExactBody` and
`Header` when you want a statement the Resource cannot later disown.
`budgets.VerifyUsageResponse` checks a response you fetched yourself, and
`signaturekey.SignResponse` and `signaturekey.VerifyResponse` sign and verify
other server responses the same way.

## Poll a deferred request

Any AAuth endpoint may answer `202 Accepted` and finish the request later
(Core, Deferred Responses). Each Agent request below has a `Begin` method that
returns an `agent.Result[T]`: either the verified result (`Value()`) or an
`agent.Pending[T]` to poll (`Pending()`).

| Request | Begin method | `T` |
| --- | --- | --- |
| Mission update | `Client.BeginMissionUpdate` | `MissionUpdateResult` |
| Mission completion | `Client.BeginMissionCompletion` | `MissionCompletionResult` |
| Audit entry | `Client.BeginAudit` | `AuditResult` |
| Authorization endpoint | `Client.BeginAuthorize` | `AuthorizationResult` |
| Sub-agent token | `Client.BeginSubagentToken` | `string` |
| Event subscription | `Client.BeginPublicSubscription`, `Client.BeginProtectedSubscription` | `EventSubscription` |
| Enrollment | `BootstrapClient.BeginEnroll` | `EnrollmentResult` |
| Agent-token refresh | `BootstrapClient.BeginRefresh`, `BootstrapClient.BeginRefreshSingleKey` | `RefreshAgentTokenResult` |

```go
result, err := client.BeginMissionCompletion(ctx, agent.MissionCompletionRequest{
	PersonServer: personServer, MissionS256: missionS256, Summary: summary,
})
for err == nil {
	if completed, ok := result.Value(); ok {
		return completed, nil
	}
	pending, _ := result.Pending()
	if question, ok := pending.Clarification(); ok {
		// question.Question() is untrusted Markdown from the person.
		if err := pending.AnswerClarification(ctx, answerFor(question)); err != nil {
			return agent.MissionCompletionResult{}, err
		}
	}
	select {
	case <-ctx.Done():
		_ = pending.Cancel(context.WithoutCancel(ctx)) // withdraw the review
		return agent.MissionCompletionResult{}, ctx.Err()
	case <-time.After(time.Until(pending.NextPollAt())):
	}
	result, err = pending.Poll(ctx, agent.PollOptions{Wait: 30 * time.Second})
}
return agent.MissionCompletionResult{}, err
```

The library never sleeps or loops; your code owns the timer and cancellation.
Each `Poll` sends one `GET` to the pending URL, signed with the credential that
signed the original request: the Agent token, the person token for
`/authorize`, the subscribe token for an event subscription, or the `hwk` or
`jkt-jwt` key for bootstrap. It never resends the original body.

- **Interval.** `RetryAfter()` is the `202`'s `Retry-After`, or five seconds
  without one. A `429` adds five seconds (or uses its own `Retry-After` when
  longer) and a `503` uses its `Retry-After`. `Poll` refuses to send before
  `NextPollAt()` and returns `*agent.PollTooEarlyError`.
- **Waiting at the server.** `PollOptions.Wait` sends `Prefer: wait`, so the
  server may hold the poll open instead of answering `202` at once.
- **Requirements.** `Requirement()` is empty while the server works, `approval`
  while someone else decides, `interaction` with `InteractionURL()` and
  `InteractionCode()` to show the person (`Interacting()` once they arrived),
  or `clarification` with `Clarification()` to answer before its deadline.
  Any other requirement is `*agent.UnsupportedRequirementError`.
- **Endings.** The terminal answer is checked exactly as an immediate answer
  is. An AAuth error such as `denied` or `abandoned` (`403`), `expired`
  (`408`) or `invalid_code` (`410`) is an `*aauth.ProblemError`. After a
  terminal answer, a malformed or relocated `202`, or a successful `Cancel`
  (a signed `DELETE`), every copy of the `Pending` returns
  `agent.ErrPendingFinished` without sending anything. After a transport
  failure the request stays pending, because the server may have answered.
- **Immediate methods.** `UpdateMission`, `CompleteMission`, `SubmitAudit`,
  `Authorize`, `RequestSubagentToken`, `RegisterPublicSubscription`,
  `RegisterProtectedSubscription`, `Enroll`, `Refresh` and `RefreshSingleKey`
  keep returning only a value. When the server defers, their error is an
  `*agent.PendingError[T]` whose `Pending()` is the same pending request, so
  nothing the server retained is lost.

`BeginAuthorize` also accepts a Resource that handles authorization itself:
`AuthorizationResult.ResourceToken()` is then empty, and `Scope()` and
`Session()` return what it authorized and the `AAuth-Access` session it issued.
Audit is fire-and-forget (Core, Audit Response): an Agent need not wait on a
pending audit entry before it continues.

Token exchange keeps its own types. `BeginExchange` and `PollExchange` handle a
pending R3 or Budget exchange like any other; an R3 or Budget pending exchange
cannot be snapshotted. `Exchange` answers a `202` with an
`*agent.PendingExchangeError` whose `Pending()` you poll with `PollExchange`.
A pending mission proposal (`BeginMission`) reports the same requirements;
answer its question with `AnswerMissionClarification` and withdraw it with
`CancelMissionProposal`. A call-chaining exchange is pending in the same way,
at the Person Server its upstream token names. A deferred call-chaining
Person-token request returns `PersonTokenResult.ChainedPending()`, an
`agent.Pending[string]` whose result is the verified downstream person token.

## Continue an AS approval or payment request

For Core requests, missionless or mission-bound, top-level, chained, or
parent-mediated for a [sub-agent](#delegate-to-a-sub-agent), set `accessserver.Config.Deferred` with an
AS-owned `accessserver.DeferredAuthorizationStore`, and
`personserver.FederatedAuthorizationConfig.Deferred` with a separate
`personserver.FederatedAuthorizationStore`. An AS policy returns `Decision.Pending` while
approval, payment, claims or the person's interaction is needed; a normal
decision grants access.

**The person at the Access Server.** When the AS needs the person, for
example to bind their Person Server or to have the resource owner approve,
its policy returns a `PendingDecision` with `InteractionURL`, the HTTPS page
the AS host serves. The AS answers with `requirement=interaction`, that URL
and `AuthorizationRequest.InteractionCode`, the code it drew for this wait;
every later poll of the wait carries the same code, so the host can keep the
pairing. The host's page compares the code the person presents with
`aauth.MatchInteractionCode`, and a later policy call grants or refuses once
the person has finished. The Person Server passes that URL and code to the
Agent in its own `202`, and the host keeps calling `AdvanceFederation` as for
approval. The Agent must declare it can reach the person:

```go
result, err := client.BeginExchange(ctx, agent.ExchangeRequest{
	PersonServer: personServer, ResourceToken: resourceToken, PresentedToken: personToken,
	Capabilities: []string{"interaction"},
})
if pending, waiting := result.Pending(); err == nil && waiting &&
	pending.Requirement() == aauth.RequirementInteraction {
	// Send the person to pending.InteractionURL() with
	// pending.InteractionCode(), then poll with PollExchange.
}
```

Without `interaction` in `capabilities` (or in the mission's captured
capabilities when a mission-bound request omits them) the Person Server
answers `403 user_unreachable` and withdraws the request at the AS. An
intermediary that meets this on a chained request chains it to its own caller
with `ChainInteraction`.

A mission-bound wait loads its mission again on every Agent poll and host
advance; once the mission is terminated the wait ends with
`403 mission_terminated` and its `termination_reason`, and its pending URL
then answers `410`. The grant is committed with the mission when it is
released, so it is never delivered past the mission's end.

The R3 and Budget limits apply to each request, not to the PS's overall
configuration: a PS with R3 and Budget enabled can still defer a separate Core
request. A local refusal returns `500 server_error` with a safe explanation.
Use `errors.As` on the diagnostic cause to inspect
`*personserver.DeferredCompositionError` and its `Reason()`; this is distinct
from `502 as_unreachable` for an unavailable or unverifiable AS response.
An AS clarification requirement, or an unsupported extension, uses the same
local refusal, including when it arrives on a later poll. `AdvanceFederation`
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
body content. Clarification forwarding and deferred R3 and Budget
combinations remain unsupported. The earliest
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
sub-agent call chaining, and no cascade from the parent's Agent-token
revocation to the child's credentials. See [CONFORMANCE.md](CONFORMANCE.md) and
[the interpretations](INTERPRETATIONS.md#a-revoked-agent-person-binding-ends-issuance-and-pending-delivery).

## Chain a call through an Access Server

A Resource that calls another Resource for its caller acts as its own Agent
Provider and Agent (the intermediary). When the downstream Resource has an
Access Server, give the four-party Person Server a chaining policy and a store
for the auth tokens it delivers:

```go
personserver.FederatedAuthorizationConfig{
	// ...
	IssuedTokens: issuedTokens, // testutil.NewIssuedAuthTokenStore() in tests
	CallChaining: &personserver.FederatedCallChainingConfig{
		BindPerson: mapUpstreamPersonToDownstreamPerson,
		Consent:    decideDownstreamRequest,
	},
}
```

The intermediary passes the token its caller presented as `UpstreamToken` in
`PersonTokenRequest`, `AuthorizeRequest`, `ExchangeRequest` and `Call`: the
person token, when it served the call on the person's identity, or the auth
token, when it required authorization. In four-party that auth token was
issued by an Access Server and delivered by this Person Server, which kept a
receipt in `IssuedTokens` naming the Agent it went to and the person token it
was obtained with. The Agent client routes by the token's `iss` (a person
token) or `ps` (an auth token), never by the intermediary's own Agent token.

The Person Server verifies the upstream token, identifies the calling Agent
from its own record of the token, and refuses the chain with
`revoked_upstream_token` once it has revoked that token, the person token it
was obtained with, or the calling Agent's Agent token or binding. It calls
`BindPerson` for a new directed person and `Consent` for the downstream
request, and posts the exact `upstream_token` with the intermediary's Agent
token to the Access Server. The Access Server verifies it again: `typ`, an
`aud` equal to the intermediary's Agent-token `iss`, and a person token issued
by, or an auth token naming, the Person Server that signed. Its policy sees the
token in `AuthorizationRequest.UpstreamPerson` or `Upstream`, and the
intermediary in `Agent`. The auth token it issues has the downstream `sub` and
expires no later than the upstream token. A bad token is
`400 invalid_upstream_token`, an expired one `expired_upstream_token`.

The downstream auth token can be the next hop's upstream token: the
intermediary's own downstream Resource chains again in the same way, as
[the repeated-hop test](integration/call_chaining_hops_test.go) does.

**Missions.** When the upstream token carries `mission_s256`, the Person
Server loads that mission of the calling Agent, passes it to `BindPerson` and
`Consent` as `Mission`, copies `mission_s256` into the downstream person token
and bounds it by the mission's expiry; the downstream auth token carries it
too. A terminated mission ends the chain with `403 mission_terminated` and its
`termination_reason`. A mission the Person Server does not hold for that Agent
is `invalid_upstream_token`. The intermediary sends no `mission_s256` of its
own; the Agent client refuses one with `UpstreamToken`, and the Person Server
answers `invalid_request`. Missions need `Missions` configured with a `Tokens`
store whose `CommitMissionPersonToken` accepts a chained record, which names
the intermediary rather than the mission's Agent (`testutil.NewMissionStore`
does).

**Budgets.** A downstream Resource token may offer a Budget on a chained
request. The Person Server sizes that hop's grant from its own offer, with
`Authorize` in three-party access or `FederatedBudgetConfig.Ceiling` sent to
the Access Server in four-party access, exactly as for an unchained request;
nothing is drawn from the upstream token. The intermediary makes the metered
call with `BeginBudgetCall`, passing the upstream token in
`BudgetCall.UpstreamToken`. A budgeted auth token can itself be the upstream
token of the next hop: the Agent client, the Person Server and the Access
Server verify its Budget claim and grant nothing from it.

**Waits.** With `Deferred`, a chained request can wait for Access Server
approval, payment, claims or interaction like any Core request. The
intermediary calls `BeginExchange`, or takes the `PendingExchangeError` from
`Exchange`, and polls with `PollExchange`. The Person Server
lets the intermediary poll although its Agent token names its own Person
Server, verifies the upstream token again on every poll, host advance and
delivery, and ends the wait no later than the upstream token. A wait whose
upstream token, resource token or calling Agent's Agent token or binding is
revoked ends with `403 revoked` and a `detail`; its pending URL then answers
`410`. The Access Server answers its own pending URL the same way.

An Access Server's `requirement=interaction` reaches the intermediary with
the AS's URL and code when it declared `interaction` in `Capabilities`, and
it chains that to its own caller as below.

Limits: chained R3 requests are refused, and a sub-agent cannot be an
intermediary. The three-party Person Server does not ask the person about a
chained request: it decides with `CallChaining.Authorize` alone.

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

Events leaves the hop from the AP to the Agent to you, but whatever carries it
must hand the Agent the token and body bytes unchanged. Implement
`agentprovider.EventInboxReader` on your store and read through the server:

```go
pending, err := provider.PendingEvents(ctx, agentID)
if err != nil {
	return err
}
for _, delivery := range pending {
	// Carry delivery.Token, delivery.Payload and delivery.ContentType to
	// the Agent, which calls Client.AcceptEvent with them.
	if err := sendToAgent(ctx, delivery); err != nil {
		return err
	}
	if err := provider.AcknowledgeEvent(ctx, agentID, delivery.Fingerprint); err != nil {
		return err
	}
}
```

`PendingEvents` returns the Agent's unacknowledged deliveries, oldest first,
and refuses one whose bytes no longer match the digests and fingerprint the AP
recorded when it accepted it. Acknowledge only after the Agent accepted the
event; an acknowledged delivery is not returned again, but an exact replay of
it from the Resource is still a duplicate. Check the read path with
`agentprovider/storetest.RunEventInboxReader`.

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

## Supervise Agents with a supervision server

AAuth Supervision lets a person hand the decisions about their Agents to a
supervision server (SS): a standing policy, a rules engine, or an
organization's governance service that answers on the person's behalf and asks
the person only when it cannot. [`example/supervision`](example/supervision)
runs one person's Agents under two supervisors in one process.

**Person Server.** Set `SupervisionConfig` on either Person Server
constructor. `Route` names each Agent's deciding supervisor: its issuer, the
directed `sub` you derive for the person with that supervisor as audience, and
the tenant you assert at connect. A person may route all their Agents to one
supervisor and particular Agents to others, for example work Agents to their
organization's. `HTTPClient` and `Admit` carry every request to a supervisor:
the person names it, and anyone can run one, so admit destinations as you do
for any outbound call.

For a routed Agent the Person Server decides nothing itself. Your `Authorize`,
`Consent`, `Missions`, `Permission` and interaction policies are not called;
`BindPerson` still resolves the person's identity after an allow. Tell the
person, when they register a supervisor, that it will see their Agents'
missions, justifications and actions, and will decide with their authority.

```go
config.Supervision = &personserver.SupervisionConfig{
	Route: func(ctx context.Context, agent personserver.SupervisedAgent) (personserver.Supervisor, bool, error) {
		return routes.Lookup(ctx, agent.Agent) // false: the person supervises it
	},
	Store:      supervisionStore,
	HTTPClient: httpClient,
	Admit:      admit,
}
```

By default the Person Server consults only a supervisor that signs its
decisions, so every decision it acts on is one it can later show was the
supervisor's; set `AllowUnsignedDecisions` to consult one that does not.

Connect when the person registers a supervisor. `ConnectSupervisor` returns
`SupervisorConnecting` with an `InteractionURL` and `InteractionCode` when the
supervisor wants the person to confirm; show them both, then call
`PollSupervisorConnect`. The Person Server also connects on first use, and
again after `unknown_sub`.

**Asks and an unavailable supervisor.** After an `ask`, or when the supervisor
cannot be reached, the Agent receives a pending response and the request waits
for the person:

```go
reviews, err := people.PendingSupervision(ctx, 50)
if err != nil {
	return err
}
for _, review := range reviews {
	// Authenticate the person and keep only their requests. Show review.Ask
	// (summary, recommendation, proposed mission) apart from what the Agent
	// asserted in review.Request, and offer review.ApplyOptions.
	err := people.ResolveSupervision(ctx, review.Reference, personserver.SupervisionAnswer{
		Answer: supervision.AnswerAllow, Apply: chosenReach,
	})
	if err != nil {
		return err
	}
}
```

`AskSupervisedAgent` puts the person's question to the Agent first; the chat
is reported to the supervisor with the person's decision. A review confers no
authority: authenticate the person before you resolve.

**Deferred decisions and events.** A supervisor that answers `202` is polled by
your host, not by the Agent's polls: call `AdvanceSupervision` for each review
in `SupervisedWaitingForSupervisor` once its next poll is due. Events and
mission reports reach a supervisor in order, before the next request to it,
after each host step, and when you call `DeliverSupervisionEvents`, for
example when a supervisor that was offline is reachable again. They include
an Agent Provider's revocation of an Agent's token, when the Person Server
also has `AgentTokenRevocations`. While supervision is configured the Person
Server also records the missions and tokens of Agents no supervisor decides
for, so that routing one later replays its active state.

**Log entries.** Every exchange with a supervisor is recorded with
`SupervisionStore.RecordSupervisionLog`: the request as signed and the
response as received, or no exchange when the supervisor was not consulted.
`supervision.VerifyExchange` verifies a signed decision from that record
alone, later, without knowing which supervisor was configured at the time.

**Supervision server.** `supervisionserver.New` serves the metadata, connect,
mission, decision and event endpoints. `Connect` accepts a Person Server for a
person at once, for instance for a tenant you govern, or asks the person to
confirm at your page; show them `ConnectConfirmation.PersonServer`, its
`PersonServerName` and the code before `ConfirmConnect`. `Decide` answers each
request with a decision, a question for the Agent, or a deferral you resolve
later with `ResolveDecision`; it sees every member the Agent sent, in
`Request.Extra` for those the request type does not name, and decides again
when a Person Server relays an updated auth-token request. `Observe` sees every event, including
`decision.resolved` with the reach the person gave their answer, which your
policy then applies. With a `SigningKey` the server publishes `jwks_uri` and
signs every decision. `RateLimit` turns a Person Server away for a while:
return a wait of whole seconds and the server answers `429 rate_limited` with
it as `Retry-After`, recording nothing, so the Person Server sends the request
again later. `testutil.NewSupervisorStore` and
`testutil.NewSupervisionStore` are in-memory stores for each side.

The limits are in [CONFORMANCE.md](CONFORMANCE.md#companion-specifications):
among them, R3 and Resource-initiated interaction are refused for a
supervised Agent.

## Return the person after an interaction

Every interaction URL accepts `?code={code}` and, from a party with a browser
flow of its own, `&callback={callback}`. The library never renders pages or
redirects by itself; your interaction page does, with these helpers:

```go
visit, err := aauth.ParseInteractionVisit(r.URL.RawQuery, aauth.InteractionVisitOptions{})
if err != nil {
	http.Error(w, "bad interaction link", http.StatusBadRequest)
	return
}
// Correlate visit.Code with the role that issued it, authenticate the person,
// and run your flow. Then, when there is a callback:
target, err := aauth.InteractionCallbackURL(visit.Callback, aauth.InteractionCallbackAccessDenied)
```

`InteractionCallbackURL` returns the callback itself when the interaction
completed (pass an empty error) and `{callback}?error={error}` when it could
not, with one of `access_denied`, `user_abandoned`, `server_error`,
`temporarily_unavailable` or `interaction_expired`. Redirect only after the
code correlates; for an unknown, used or rate-limited code, show an error page
instead, so your page cannot be used as an open redirector. A callback must be
an HTTPS URL without query or fragment. Set `AllowLoopbackCallback` only when
you checked that the Agent's metadata sets `localhost_callback_allowed`.

**Pages this library hosts.** The Person Server's consent and person-token
pages, and a Resource-managed session page, retain the callback with the
pending request. Correlate the visit with
`ConsumeAuthorizationInteractionVisit`, `ConsumePersonTokenInteractionVisit` or
`ConsumeSessionInteractionVisit` instead of the `...Code` methods; a callback
that does not correlate is never retained. After your own decision, redirect to
the interaction's `CompletionURL()`, or to `FailureURL(err)`: `access_denied`
after a denial, `user_abandoned` after `AbandonAuthorizationInteraction`, and
`server_error` after a failure or invalidation. When the request ended without
your decision, for example by expiring while the person was away,
`AuthorizationCallbackURL`, `PersonTokenCallbackURL` and `SessionCallbackURL`
return the callback with the error for its state (`interaction_expired` for
expiry). Once the Agent has collected the result the store reports the request
as gone, which these read as `server_error`, so prefer the interaction's own
URLs right after a decision. Each returns an empty string when the person came
without a callback; show your own completion page then. A custom store keeps
`Callback` from the code presentation that consumed the code
(`AuthorizationCodePresentation`, `PersonTokenCodePresentation`,
`resource.SessionCodePresentation`) and returns it in its snapshot;
`RunDeferredAuthorization`, `RunDeferredToken` and the session storetest check
it.

**Agent.** To send the person yourself with a callback, build the link with
`aauth.FormatInteractionVisitURL(pending.InteractionURL(), pending.InteractionCode(), callback)`.
Publish the base of your callbacks with `agentprovider.Config.CallbackEndpoint`
(and `LocalhostCallbackAllowed` for a loopback callback). At your callback
endpoint, `aauth.ReadInteractionCallback(r.URL.RawQuery)` returns nil, or an
`aauth.InteractionCallbackError` you must surface: do not treat the pending
request as completable. Its pending URL stays authoritative and reports the
same outcome as a polling error, which `PollingError()` names.

### Resolve a Resource's own interaction before consent

A Resource that needs its own flow first, such as an OAuth authorization at a
third-party service, sets `resource.PSAuthorizationConfig.InitiatedInteraction`:
`URL` (its HTTPS interaction page), `Require` (decides per verified
Person-token challenge) and `Store` (`testutil.NewInitiatedInteractionStore`
in tests). The Resource token then carries an `interaction` claim naming
`{URL}/{reference}` and a fresh code. Your page calls
`ConsumeInitiatedInteraction(ctx, reference, visit)`, runs the flow for
`Person()`, and redirects to `CompletionURL()`, or to `FailureURL(err)` when
the flow cannot finish. The code is single use, allows three failed attempts,
and dies with the Resource token.

The Person Server sets `personserver.PSAuthorizationConfig.ResourceInteraction`
with `Policy` (its own interaction page, lifetime and polling interval),
`CallbackURL` and `Admit` (egress admission for the Resource's URL), plus an
`AuthorizationInteractions` store that implements
`personserver.ResourceInteractionAuthorizationStore`
(`testutil.NewDeferredAuthorizationStore` does). A token request carrying the
claim always gets a `202`; an Agent that did not declare `interaction` gets
`403 user_unreachable`. The Agent uses `BeginExchange` and `PollExchange`;
`Exchange` refuses such a Resource token. Your Person Server pages then:

1. On the interaction page, call `ConsumeAuthorizationInteractionVisit`,
   show the interstitial saying the Resource needs additional permissions, and
   redirect to `RedirectToResourceInteraction(ctx, interaction, "")`, which uses
   the callback the visit carried.
   An interaction URL that is not HTTPS or that `Admit` refuses ends the
   request with `server_error` (`ErrResourceInteractionRefused`).
2. On `{CallbackURL}/{reference}/{flow}`, call
   `ReceiveResourceInteractionCallback(ctx, reference, flow, r.URL.RawQuery)`.
   An error callback ends the request with the mapped polling error
   (`access_denied` → `denied`, `user_abandoned` → `abandoned`,
   `interaction_expired` → `expired`, the others → `server_error`) and is
   returned as an `aauth.InteractionCallbackError`. Otherwise show your consent
   and call `ApproveAuthorizationInteraction` or `DenyAuthorizationInteraction`;
   approval before the Resource returned the person is
   `ErrResourceInteractionPending`. Once the Resource withdraws its Resource
   token, both steps refuse with `ErrResourceTokenRevoked` and the Agent's
   next poll receives `revoked`.
3. Redirect to `AuthorizationCallbackURL(ctx, reference)`, the Agent's own
   callback with the outcome, or show a completion page when it is empty.

The flow is three-party and missionless. Call chaining, R3, missions and a
federated Person Server refuse the claim. See
[the end-to-end test](integration/resource_initiated_interaction_test.go).

### Chain a downstream interaction to your caller

A Resource that calls another server as an Agent may meet a `202` with
`requirement=interaction`. Set `ChainedInteractions` on
`resource.PSAuthorizationConfig` or `FederatedAuthorizationConfig` with `URL`,
`CallbackURL`, `Lifetime`, `RetryAfter` and `Store`
(`testutil.NewChainedInteractionStore` in tests). In your Protected handler,
pass the downstream requirement to `ChainInteraction(w, r, downstream)`. It
answers your caller with your own `202`, your own code, and your own pending
URL under `/chain/pending/`. It writes nothing and returns
`ErrChainedInteractionUndeclared` when the caller did not send
`AAuth-Capabilities: interaction`. Keep the downstream pending value with
`Reference()`; the library does not hold it for you.

On `{URL}/{reference}`, `VisitChainedInteraction(ctx, reference, visit)` returns
the downstream interaction link with your own per-flow callback. On
`{CallbackURL}/{reference}/{flow}`, `ReceiveChainedInteractionCallback` returns
the interaction, or ends it with the mapped polling error when the downstream
host sent an error. Poll your downstream request, which stays authoritative,
finish the original request, and call `CompleteChainedInteraction` with its
result (or `FailChainedInteraction` with the downstream polling error). Then
redirect to `ChainedInteractionCallbackURL`. Your caller receives the result
once; a later poll is `410`, and a poll signed by any other key is an empty
`404`. The deadline never passes the caller's Auth token, and only Core Auth
tokens can be chained.

The original Agent reads the `202` from `Do` with `ReadInteractionCall`, sends
the person to the interaction, and polls with `PollInteractionCall` and the
same Auth token. An intermediary whose own call-chaining exchange meets an
interaction, or an Access Server wait, gets a pending exchange from
`BeginExchange` (or from `Exchange`'s `PendingExchangeError`) and polls the
Person Server its upstream token names; such a pending exchange cannot be
snapshotted. A call-chaining Person-token request that meets one returns
`ChainedPending()`, polled the same way. See
[the end-to-end test](integration/interaction_chaining_test.go).

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
| `NewMissionStore` | PS Person-token records (the `Tokens` store, with or without missions, found also by upstream token and by Agent), mission lifecycle, proposals, permissions, audit and R3 issuance |
| `NewMissionInteractionQuestionStore` | The same mission state plus questions, sharing one transaction boundary |
| `NewMissionInteractionRelayStore` | The same mission state plus interaction relays, sharing one transaction boundary |
| `NewPermissionStore`, `NewInteractionQuestionStore`, `NewInteractionRelayStore` | Separate missionless PS stores |
| `NewEnrollmentStore`, `NewAgentTokenRevocationStore` | AP enrollment or Resource revocation, respectively |
| `NewDeferredAuthorizationStore` | PS consent, clarification and Resource-initiated interaction progress, sharing one transaction boundary |
| `NewInitiatedInteractionStore`, `NewChainedInteractionStore` | Resource-initiated interaction codes, or chained interactions and their results, respectively |
| `NewAccessAuthorizationStore`, `NewFederatedAuthorizationStore` | Separate AS request retention and PS federation continuation |
| `NewBudgetStore` | Resource fixed-price token consumption and person totals |
| `NewR3DocumentStore`, `NewR3IssuanceStore` | Resource documents or role-local issuance audit, respectively |
| `NewIssuedAuthTokenStore`, `NewAuthTokenStatusStore` | PS-issued Auth tokens and four-party delivery receipts, found by reference or by the token they were issued against; or Resource revocation status, respectively |

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
with Ed25519 keys, and answer any other scheme with `unsupported_scheme`. A
Resource can also accept clients outside AAuth (see below). An
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

### Accept clients outside AAuth at a Resource

AAuth Agents sign with the `jwt` scheme, and servers with `jwks_uri`. A
Resource that also serves clients outside AAuth may accept further schemes on
its protected routes. Set `FurtherSchemes` on any Resource constructor:

```go
resource.AgentIdentityConfig{
	// ...
	FurtherSchemes: &resource.FurtherSchemesConfig{
		Schemes:    []signaturekey.Scheme{signaturekey.SchemeHWK, signaturekey.SchemeJWKS},
		Algorithms: []string{jose.ES256Algorithm}, // for hwk keys
		JWKS:       keyResolver,
		Protected:  otherClients,
	},
}
```

A request under one of these schemes is verified by that scheme's verifier and
served by `FurtherSchemes.Protected`, never by the AAuth handler. There,
`resource.SignerFromContext` returns the scheme, the signer (a key thumbprint
URI, a `jwks_uri` id, a `jwks` URL or an `x5u`) and the verifying key. Such a
signer is not an AAuth Agent and carries no person or grant. AAuth requests are
unchanged. Every `Accept-Signature-Scheme` the protected routes send, on an
unsigned challenge or on `unsupported_scheme`, lists `jwt` and then your
schemes in your order; `Accept-Signature-Alg` lists Ed25519 and your
algorithms; an `hwk` or `x509` key may use them, while keys found through
`jwks`, `jwks_uri` or `jkt-jwt` stay Ed25519. Schemes may be `hwk`, `jkt-jwt`,
`jwks_uri`, `jwks`, `x509` and `cached`. `x509` needs an `X509` callback that returns the chain, anchors and
CRLs for an `x5u`. `cached` needs `Cache`, an `AssertionCache`, and `jkt-jwt`:
the Resource then issues `Signature-Key-Cache` to a `jkt-jwt` client that
asks, and resolves its `cached` requests. The authorization and revocation
endpoints keep their AAuth schemes.

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

Install the module at a commit on `main`; it has no release tags:

```sh
go get gitlab.com/sidecat-dev/aauth-go@0e2447b
```

`go get` records the commit in `go.mod` as the pseudo-version
`v0.0.0-20261031210612-0e2447bc05b0`. Review and commit `go.mod` and `go.sum`;
these editor drafts and APIs are still evolving. To move to a later commit,
run `go get` again with its hash.

For in-process development, use `https://resource.example` as in the runnable
example; no DNS or listener is needed. With a local TLS listener, keep that
logical request host and route its connection to loopback through your test
transport. Changing `Issuer` alone does not make a request to
`127.0.0.1:8080` match it. A key resolver that fetches through such a
transport needs `TransportEnforcesEgress: true`, because the transport, not
the resolver, decides where connections go (see
[Verify an Agent at your HTTP endpoint](#verify-an-agent-at-your-http-endpoint)).
[Get started](docs/getting-started.md) runs an Agent and a Resource this way.
The [local walkthrough](walkthrough/local) shows separate TLS processes and
certificates at its declared module pin. That pin is from before the resolver
checked destinations, so the walkthrough's resolver omits the setting; a copy
of its client at a current commit needs it.

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

The standalone `walkthrough/` modules deliberately pin older commits. Their
tests exercise those commits, not this checkout.

To try an unmerged checkout in a separate module, start in the `aauth-go`
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
placeholder `v0.0.0` is satisfied by the local replacement; no such version
exists. For an existing application, apply the same absolute replacement to
its module and run `go mod tidy` after adding imports. A replacement does not
publish or pin the checkout's contents, so record the checkout commit when
sharing results. Remove the replacement and `go get` a commit on `main`
before distributing a module intended to work without your local checkout.
