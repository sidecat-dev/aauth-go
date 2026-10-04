# Two-resource call chain over TLS processes

This standalone Go consumer runs an Agent/Agent Provider, a Person Server,
an Orders Resource that acts as an Agent, and an Inventory Resource as four
separate processes. An authorized `orders.fulfill` request produces one
`inventory.reserve` action. The Inventory response identifies the verified
directed person, intermediary proof key, scope, expiry and action count.

The external dependency is exactly
`gitlab.com/sidecat-dev/aauth-go v0.0.0-20261004022946-1d27163e815d`, from
[public commit 1d27163e815d9a6dd95eed2ba7293a1fc428682a](https://gitlab.com/sidecat-dev/aauth-go/-/commit/1d27163e815d9a6dd95eed2ba7293a1fc428682a).
The module has no `replace` directive. Its parent checkout may be at another
revision; it supplies the walkthrough source, not the library implementation.

## Build and initialize

Requires Go 1.25 or later. From this directory:

```sh
export GOWORK=off
go build -p=1 -o ./aauth-callchain .
./aauth-callchain --help
state_dir="$(mktemp -d)"
./aauth-callchain init --state "$state_dir"
```

`init` prints only public identity information. It generates a temporary CA,
24-hour hostname certificates, separate protocol keys and one-hour Agent
tokens in the private state directory. It refuses to overwrite an initialized
configuration. No system trust, DNS, hosts file or service configuration changes
are needed. Private keys and tokens use mode `0600`.

Top-level `-h`, `--help` and `help` show the command overview successfully
without requiring or accessing state. Use `aauth-callchain COMMAND --help`
(or `-h`) for that command's options. Starting and stopping the four processes
uses the shell process IDs shown below; there are no start/stop subcommands.

Default listeners are `127.0.0.1:18443`, `:19443`, `:20443` and `:21443` for
Agent, Person Server, Orders and Inventory respectively. To choose other ports,
pass `--agent-address`, `--person-address`, `--orders-address` and
`--inventory-address` to `init`. All listeners must use loopback IP addresses
and distinct, nonzero ports.

## Start, use and stop

In the same shell, start all four roles and retain their process IDs:

```sh
./aauth-callchain serve --state "$state_dir" --role agent & agent_pid=$!
./aauth-callchain serve --state "$state_dir" --role person & person_pid=$!
./aauth-callchain serve --state "$state_dir" --role orders & orders_pid=$!
./aauth-callchain serve --state "$state_dir" --role inventory & inventory_pid=$!
```

Once `status` reaches all four roles, run the unsigned control, inspect the
zero action count, then authorize one call:

```sh
./aauth-callchain status --state "$state_dir"
./aauth-callchain probe --state "$state_dir" --kind unsigned
./aauth-callchain status --state "$state_dir"
./aauth-callchain call --state "$state_dir"
./aauth-callchain status --state "$state_dir"
```

The unsigned probe reports `refused` with HTTP `401`, and the count stays zero.
The authorized call reports `completed`, `person-at-orders`,
`person-at-inventory`, `inventory.reserve`, the intermediary key thumbprint
printed by `init`, and `consequence_count: 1`. The downstream Person and Auth
token expiries must not exceed `upstream_exp`. Metadata and JWKS request counts
in `status` show that discovery crossed the TLS sockets.

The original Auth token lasts 20 seconds. Wait until the call's `upstream_exp`
plus one second, or simply wait 21 seconds after the successful call, then
present that exact retained credential with a fresh HTTP signature:

```sh
sleep 21
./aauth-callchain probe --state "$state_dir" --kind expired
./aauth-callchain status --state "$state_dir"
```

Orders reports HTTP `401` and `Signature-Error: error=expired_jwt`; Inventory's
count stays one. Calling the expired probe too early returns a wait instruction
and sends no application request.

Stop the processes before deleting their private state:

```sh
kill "$agent_pid" "$person_pid" "$orders_pid" "$inventory_pid"
wait "$agent_pid" "$person_pid" "$orders_pid" "$inventory_pid"
rm -rf -- "$state_dir"
```

No call or probe retries a consequence automatically. Each explicit `call`
requests new authorization and can add another Inventory action. An uncertain
response does not prove whether Inventory acted; this consumer supplies no
idempotency or recovery protocol for that case.

## Protocol and application boundaries

TLS verifies hostnames against the temporary CA. A normal `http.Transport`
maps the four HTTPS hostnames to their configured loopback TCP listeners;
there is no in-process request transport or disabled certificate verification.
Every role uses `signaturekey.NewHTTPKeyResolver` to acquire metadata and JWKS.
Orders publishes collocated AP and Resource metadata with distinct issuer
keys and uses a third key for its own Agent request proofs.

The Person Server's application policy knows one original person and maps
that person to a different directed subject at Inventory. It independently
authorizes Inventory's scope; the scope need not be a subset of Orders' scope.
The intermediary's own Agent token names a different Person Server, so the
successful chain relies on routing from the upstream token's `ps`.

This is one immediate, missionless, accountless, same-PS, Auth-token upstream
hop. The library correction targets the following clauses in
[AAuth Protocol -11, editor commit 28e8258f8153a2a51a709c53ebc9618f941564e4](https://github.com/dickhardt/AAuth/blob/28e8258f8153a2a51a709c53ebc9618f941564e4/draft-hardt-oauth-aauth-protocol.md):

| Selected source clause | Consumer evidence |
| --- | --- |
| Person Token Structure `exp`, source line 863 | Downstream Person-token expiry is no later than the upstream expiry. |
| Auth Token Structure `exp`, source line 1775; Call Chaining, line 1850 | Downstream Auth-token expiry is no later than the upstream expiry. |
| Upstream Token Verification steps 1–3, lines 1832–1834; Call Chaining, lines 1852–1856 | Actual role exchange, distinct intermediary proof key, upstream PS routing and downstream directed subject. |

The library identifies the calling Agent under step 4 from the Person Server's
own issuance record of the upstream token, answers `revoked_upstream_token`
when that Agent's token is revoked, and applies the `presented_token` expiry
ceiling. Upstream Person tokens, missions/accounts, federation, deferred
chaining, sub-agent chaining, repeated hops and cascade remain unadopted. This consumer does not claim
full Protocol -11 conformance or interoperability with another implementation.

Person-token bindings, discovery caches and Inventory's action counter belong
to their processes. Restart loses them. Files retain only generated setup
material and the last upstream credential for the explicit expiry probe;
they do not provide protocol-state persistence. The shared private directory
is a development setup, not OS isolation between roles. There is no enrollment
UI, credential refresh, production persistence or public hosting automation.
Initialize fresh state when Agent tokens or TLS certificates expire.

## Developer verification

```sh
GOWORK=off go test -p=1 -count=1 -v ./...
GOWORK=off go test -p=1 -race -count=1 -v ./...
GOWORK=off go vet ./...
```

`TestTLSProcessCallChain` starts four real TLS child processes and a separate
caller, checks one authorized consequence and both refusals, verifies actual
network discovery, and waits for natural credential expiry. It builds the
consumer unless `AAUTH_CALLCHAIN_BINARY` names an already built executable.
Developer checks are author evidence. Independent installed/user acceptance
must identify and inspect the exact executable and its observations separately.
