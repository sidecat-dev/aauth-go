# Errors

This page lists what the servers in this library answer when they refuse, how
each answer reaches your Go code, and what the caller does about it. Terms are
defined in [How AAuth works](how-aauth-works.md).

A refusal reaches the agent in one of five ways:

| Status and header | Meaning | Where |
| --- | --- | --- |
| `401` with `Signature-Error` | The signature, or the token that carries the key, failed a check | [Signature and token errors](#signature-and-token-errors) |
| `401` with `AAuth-Requirement` | The server needs a different token | [How AAuth works](how-aauth-works.md#challenges-and-waiting) |
| `403` from your handler | Everything checked out, and your policy said no | [Refusals by policy](#refusals-by-policy) |
| `400`, `403`, `500` or `502` with an `error` in the body | A Person Server or Access Server refused a token request | [Token endpoint errors](#token-endpoint-errors) |
| Any status but `202` from a pending URL | A request that waited ended without success | [Polling errors](#polling-errors) |

Error bodies from the library are `application/problem+json`, with the code in
`error` and sometimes an explanation in `detail`. For a `401`, the
`Signature-Error` header is the code to act on, not the body.

## In Go

Every method of `agent.Client` returns its failures as an `*agent.Error`,
which names the step (`Operation`) and wraps the cause. Use `errors.As` to
reach the cause:

| Cause | When | Read |
| --- | --- | --- |
| `*signaturekey.Error` | a `401` with `Signature-Error` | `Code`; `RequiredInput`, `AcceptedSchemes` and `AcceptedAlgorithms` when the server sent them |
| `*aauth.ProblemError` | any other refusal with a problem body | `Status`, `Code`, `Detail`; for missions, `MissionStatus` and `TerminationReason` |
| `*agent.PersonTokenRequiredError` | a Resource refused a revoked Auth token and asks for a Person token | `Requirement()`; `errors.As` also finds the `*signaturekey.Error` |
| `*agent.PendingError`, `*agent.PendingExchangeError`, `*agent.MissionProposalPendingError` | a method that returns only a finished result got `202` | `Pending()`: the request to poll. Nothing is lost. |
| `*agent.PollTooEarlyError` | a poll before the server's `Retry-After` passed; nothing was sent | `NextPollAt` |
| `agent.ErrPendingFinished` | a poll after the request ended; nothing was sent | stop polling |
| `*agent.BudgetCallUncertainError` | a metered call whose answer cannot be trusted | `AssumedCost()`; see [Budgets](features/budgets.md#when-the-budget-runs-out) |

A response that is neither, such as a `403` your own handler wrote as plain
text, is not an error: `CallAsAgent` and `Do` return it as the response.

<!-- sample: agent/example_test.go -->
```go
var signature *signaturekey.Error
var problem *aauth.ProblemError
switch {
case errors.As(err, &signature):
	// signature.Code is the Signature-Error code.
	fmt.Println("Signature-Error:", signature.Code)
case errors.As(err, &problem):
	// problem.Code is the error member of the body; problem.Status the HTTP status.
	fmt.Println("refused:", problem.Status, problem.Code)
}
```

On the server side, wrap a role's handler in `diagnostics.Handler` to see the
local cause of each refusal it sends; the caller sees only the code
([Diagnose a refused request](../USE-IN-YOUR-SERVICE.md#diagnose-a-refused-request)).

## Signature and token errors

The code is in the `error` member of the `Signature-Error` header, for example
`Signature-Error: error=invalid_input, required_input=("@method" "@authority")`.
In Go it is `signaturekey.Error.Code`, one of the `signaturekey.Error...`
constants.

| Code | What it means | What the caller does |
| --- | --- | --- |
| `invalid_signature` | The signature is missing, malformed or does not verify; a covered body or field no longer matches; or its `created` time is more than 60 seconds old. | Sign again, last, after the URL, headers and body are final. Send to the server's own origin. Check the clock. |
| `invalid_input` | The signature does not cover something the server requires, or the body is over the server's limit. `required_input` lists what is missing. | Sign again covering the listed components. `CallAsAgent` covers what the Resource's metadata lists; `CallAsAgentWithComponents` takes a list. |
| `clock_skew` | The signature's `created`, or the token's `iat`, is more than 60 seconds ahead of the server's clock. | Fix the clock, or wait and send again. |
| `invalid_jwt` | The token is malformed, its signature fails, it is the wrong kind of token, or it is for another audience. | Get a new token from its issuer, for this server. |
| `expired_jwt` | The token has expired. | Get a new one: a new Agent token, or a new Person or Auth token. |
| `revoked_jwt` | The token was withdrawn. | Do not send it again. If the Resource also asks for a Person token, you get `*agent.PersonTokenRequiredError`: start again from a Person token. |
| `invalid_key` | The key could not be parsed or the `Signature-Key` header is malformed, or the server could not use the token issuer's keys: it does not trust that issuer, or it could not fetch them. | Do not retry with the same issuer. Either the server does not accept your Agent Provider, which is a setup question between the parties, or its key resolver refused the fetch; see [Fetch issuer keys](roles/resource.md#fetch-issuer-keys). |
| `unknown_key` | The issuer is trusted, but its key set has no key with this ID. | Retry later, once the server has refreshed the issuer's keys. |
| `unsupported_scheme` | The key was presented in a way the server does not accept. `Accept-Signature-Scheme` lists the ways it does. | AAuth agents present their token under `jwt`, which `agent.Client` does. |
| `unsupported_algorithm` | The signing algorithm is not accepted. `Accept-Signature-Alg` lists those that are. | Sign with Ed25519 or ES256. AAuth tokens and agent keys in this library use one of the two. |
| `cache_miss` | A cache identifier the server issued earlier is not known any more. | Send the full token again. |
| `issuer_missing`, `issuer_mismatch` | The issuer's metadata has no `issuer`, or names another one. | Nothing on the agent's side: the issuer's metadata needs fixing. |
| `invalid_request` | The verifier itself is misconfigured. | Nothing on the agent's side. |

## Refusals by policy

A `403` without `Signature-Error` means the request was authenticated and then
refused. Signing again will not help. Tell the person, or ask for different
access.

- From your own handler, the body is whatever your handler wrote.
- From a `resource.NewPSAuthorization` or `NewFederatedAuthorization` Resource,
  `403 access_denied` means the Auth token does not grant what this route
  needs: a scope, an R3 operation, or a Budget on a metered route.
- From a Person Server, Access Server or supervision server, `403
  access_denied` means its policy refused.

## Token endpoint errors

These come from `POST /person` and `POST /token` at a Person Server, and from
an Access Server's `POST /token`, in the body's `error` member. The `_token`
codes name the request parameter that failed.

| Code | Status | What the caller does |
| --- | --- | --- |
| `invalid_request` | 400 | Fix the request: malformed JSON, a missing or unknown member. |
| `invalid_agent_token` | 400 or 401 | The Agent token, or the signature with it, failed. Get a new Agent token. |
| `expired_agent_token` | 400 | Get a new Agent token. |
| `person_token_denied` | 403 | The Person Server will not say which person this agent acts for: the agent is not linked to a person, or the link was revoked. |
| `user_unreachable` | 403 | The person has to be asked, and the agent did not say it can reach them. Send `Capabilities` with `interaction`. |
| `access_denied` | 403 | The person, or the policy, refused. |
| `invalid_resource_token` | 400 | The Resource token is malformed, fails its signature, or does not match the presented token. Call the Resource again for a new one. |
| `expired_resource_token` | 400 | Call the Resource again for a new Resource token. |
| `revoked_resource_token` | 400 | The Resource withdrew it. Call the Resource again. |
| `invalid_presented_token` | 400 | The presented Person or Auth token is malformed, fails its signature, or is not the one the Resource token names. Get a new Person token. |
| `expired_presented_token` | 400 | Get a new Person token, then a new Resource token. |
| `revoked_presented_token` | 400 | Get a new Person token, then a new Resource token. |
| `invalid_upstream_token` | 400 | In call chaining, the upstream token is malformed, fails its signature, or was not issued for this intermediary. |
| `expired_upstream_token` | 400 | The caller must authorize again at the intermediary. |
| `revoked_upstream_token` | 400 | The upstream token, the calling agent's Agent token, or its link to the person was revoked. Do not retry with it. |
| `invalid_subagent_token`, `expired_subagent_token` | 400 | The sub-agent's token is malformed, does not name this parent, or has expired. The parent gets a new one. |
| `invalid_budget` | 400 | A Budget in the request or token is malformed, uses an unknown unit, or is larger than the offer. |
| `clock_skew` | 400 | A token sent as a parameter has an `iat` ahead of the server's clock. Wait and send it again. |
| `mission_terminated` | 403 | The mission behind this request has ended. Stop using it. |
| `as_unreachable` | 502 | The Person Server could not reach, or could not use the answer of, the Resource's Access Server. Try again later. |
| `server_error` | 500 | Something failed inside the server, or a policy callback returned an error that was not a refusal. Try again later. |

## Polling errors

A pending URL answers `202` while the request waits. Any other answer ends it,
and the Go client returns it from `Poll`:

| Code | Status | Meaning | What the caller does |
| --- | --- | --- | --- |
| `denied` | 403 | The person, or a supervisor, refused. | Stop; tell the person. |
| `expired` | 408 | Nobody answered in time. | Start again if the work still needs it. |
| `invalid_code` | 410 | The request is unknown here or already finished. | Stop polling; do not send it again. |
| `revoked` | 403 | A token the request depends on was revoked while it waited. | Stop. |
| `mission_terminated` | 403 | The mission ended while the request waited. | Stop. |
| any | 429 or 503 | The server is busy. | Poll later. On these, the Go client keeps the request and moves `NextPollAt` later: it backs off on `429` and honors `Retry-After` on `503`. |

## Next

- [Agent](roles/agent.md): where these errors come back.
- [Conformance scenarios](https://gitlab.com/sidecat-dev/aauth-conformance/-/tree/dbf640d/scenarios): the refusals the conformance suite checks
  on the wire, scenario by scenario.
