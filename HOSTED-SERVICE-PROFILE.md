# Hosted service profile

This profile composes the repository's implemented AAuth journeys into a
practical first deployment for a hosted service and its users' local agents.
It is an implementation profile, not an additional AAuth specification.

The profile is intentionally narrower than full conformance. It answers one
deployment question: what must work before a hosted service can enroll a local
Agent, authorize bounded service operations, survive restart, and remove that
Agent's ability to obtain new credentials?

## Roles

| Role | Typical deployment | Responsibility |
| --- | --- | --- |
| Agent | User-controlled machine | Holds its private proof key and makes explicit protocol calls. |
| Agent Provider | Local or hosted account service | Enrolls the durable key, assigns the Agent identifier, and issues short-lived Agent tokens. |
| Person Server | Hosted account service | Binds the Agent to the person, records approval-only missions, decides local-action permission, and issues Person or three-party Auth tokens. |
| Resource | Hosted connector or API | Keeps service credentials private, publishes bounded operations, enforces grants and hard Budget caps, and executes approved calls. |
| Access Server | Hosted authorization service | Issues four-party Auth tokens when Resource policy is independent from the Person Server. |

A single process may host several roles. Role identifiers, keys, policy, and
retained state remain distinct even when their handlers share a server.

## Minimum launch journey

1. The Agent creates one durable key and submits host-selected enrollment
   evidence through `agent.BootstrapClient.Enroll`.
2. The Agent Provider authenticates the signed request, applies account policy,
   and atomically binds the key to one stable Agent through
   `agentprovider.EnrollmentStore`.
3. The Agent obtains a short-lived Agent token with either a delegated current
   key or the simpler single-key refresh profile.
4. The Agent uses that token to request one of:
   - local-action permission from the Person Server;
   - three-party authorization from the Person Server; or
   - four-party authorization through the Person Server and Access Server.
5. The Resource executes only the operation and Budget admitted by the verified
   token. A connector retains any third-party service credential; the Agent
   receives AAuth authority, not that credential.
6. Each role can be reconstructed around the same retained stores. Exact
   enrollment, refresh, authorization, and execution replays recover their
   retained results instead of repeating consequences.
7. An authenticated host disables or revokes the enrollment with
   `EnrollmentStore.TransitionEnrollment`. New refreshes stop immediately.
   The issuing Agent Provider can also sign the exact `(iss, jti)` of an
   already-issued Agent token to the configured Person Server and each known
   direct Agent-identity Resource revocation endpoint. Those recipients then
   refuse later requests before policy or application dispatch. Other
   recipients still rely on the token's signed expiry until they receive and
   enforce a corresponding revocation signal; the protocol defines no Resource
   registry or automatic fan-out.

Run the complete in-process composition spine with:

```sh
go run ./example/hostedservice
```

That example proves the features can share one configured environment. It
charges one MCP connector call, verifies that an exhausted-Budget step-up is
returned before a second connector dispatch, exchanges the replacement token,
and resumes one connector call under the fresh grant. The focused examples
below provide deeper evidence for individual paths, including exact refresh
replay:

```sh
go run ./example/bootstrap
go run ./example/permission
go run ./example/threeparty
go run ./example/fourparty
go run ./example/r3threeparty
go run ./example/budget
go run ./example/mission
go run ./example/revocation
```

## Required launch capabilities

| Capability | Current implementation boundary |
| --- | --- |
| Enrollment and renewal | Hosted two-key and single-key profiles in `agent` and `agentprovider`; endpoints and application evidence are host choices because Bootstrap does not standardize them. |
| Enrollment suspension and revocation | Host-authenticated atomic state transition; disabled is reversible, revoked is terminal, and exact retries recover the retained transition. |
| Local action | Immediate or explicitly deferred Permission Endpoint decision; the application executes only after a typed grant. |
| Hosted account identity | Person tokens use the `(ps, sub)` namespace and are directed to one Resource. |
| Service authorization | Three-party and four-party Auth-token journeys with explicit Agent calls and no hidden polling. |
| Operation authorization | MCP and OpenAPI R3 class and per-call journeys. The direct MCP class path composes with a fixed Budget in one protected call. Other registered vocabularies are not launch requirements. |
| Human approval | Approval-only missions and deferred permission decisions with application-authenticated host review. |
| Spending or usage limit | Fixed-price, hard-cap Budgets with atomic Resource charging. The direct MCP composition verifies the operation before charging, preserves the R3 reference on step-up, refuses exhaustion before dispatch, and resumes only after explicit replacement exchange. A commercial billing ledger remains an application concern. |
| Restart and replay | Applications provide stores satisfying the public role-local `storetest` contracts, including R3 document, R3 issuance, and Budget charging; services may be reconstructed around those retained stores. |
| Third-party credential isolation | The connector stores and uses its OAuth or API credential. AAuth conveys the permitted operation and limits, never the credential itself. |

## Host responsibilities

The library does not authenticate an administrative web session, validate
platform attestation, store OAuth credentials, render untrusted text, schedule
polls, or choose business policy. The host must:

- authenticate people and administrators before invoking review or enrollment
  transition methods;
- supply durable, transactionally correct store adapters;
- run each applicable role-local `storetest` suite against those adapters,
  including `resource/storetest.RunR3Document`,
  `r3/storetest.RunIssuance`, and `resource/storetest.RunBudget` for the
  operation-and-Budget path;
- keep private keys and third-party credentials out of Agent-visible values;
- use short Agent-token lifetimes appropriate to the delay between revocation
  and expiry;
- sanitize untrusted Markdown before display;
- drive every retry or poll explicitly; and
- retain application billing separately from AAuth Budget authority.

## Deferred from this profile

The first hosted profile does not require every AAuth deployment combination.
It deliberately defers:

- complete role journeys for every R3 vocabulary;
- variable-price and streaming Budget profiles;
- third-party login, whose current Core flow is internally incomplete;
- arbitrary recursive delegation and unbounded call chains;
- a complete cross-endpoint mission log and mission clarification control plane;
- platform-specific attestation and durable-key replacement; and
- independent-implementation interoperability claims.

These omissions remain visible in [CONFORMANCE.md](CONFORMANCE.md) and
[JOURNEYS.md](JOURNEYS.md). They do not weaken the behavior claimed by this
profile.

## Deployment acceptance

A deployment of this profile is ready only when it has exercised, across real
process restarts:

- [ ] enrollment and exact refresh replay;
- [ ] one local-action permission;
- [ ] one hosted Resource authorization and protected call;
- [ ] one MCP or OpenAPI operation grant;
- [ ] one fixed-price Budget charge, over-cap refusal before dispatch, and
      explicit replacement-grant recovery;
- [ ] one approval-only mission when the product exposes missions;
- [ ] host suspension or revocation followed by refused refresh; and
- [ ] expiry or explicit revocation at every recipient the deployment promises
      will invalidate a previously issued credential.
