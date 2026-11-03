# Two-resource call chain over TLS processes

This standalone Go consumer runs an Agent/Agent Provider, a Person Server,
an Orders Resource that acts as an Agent, and an Inventory Resource as four
separate processes. An authorized `orders.fulfill` request produces one
`inventory.reserve` action. The Inventory response identifies the verified
directed person, intermediary proof key, scope, expiry and action count.

The external dependency is exactly
`gitlab.com/sidecat-dev/aauth-go v0.0.0-20261004022946-1d27163e815d`, from
[public commit 1d27163e815d9a6dd95eed2ba7293a1fc428682a](https://gitlab.com/sidecat-dev/aauth-go/-/commit/1d27163e815d9a6dd95eed2ba7293a1fc428682a).
The module has no `replace` directive. Your checkout supplies this guide and
its Go files; the build always links the pinned library commit above, which
carries the token-expiry correction described under
[Protocol and application boundaries](#protocol-and-application-boundaries).

## Build and initialize

Requires Go 1.25 or later. From this directory:

```sh
export GOWORK=off
go build -p=1 -o ./aauth-callchain .
./aauth-callchain --help
state_dir="$(mktemp -d)"
./aauth-callchain init --state "$state_dir"
```

`init` prints only public identity information, including `intermediary_key`,
the intermediary's proof-key thumbprint. It generates a temporary CA,
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

A running role prints nothing. `status` asks each role for its counters and
changes none of them. It exits nonzero with an error, and prints no partial
result, until all four roles answer; exit `0` means all four are reachable, so
repeat it until then. A role that cannot start, for example because its port is
in use, exits with an error instead.

Then run the unsigned control, inspect the zero action count, and authorize one
call:

```sh
./aauth-callchain status --state "$state_dir"
./aauth-callchain probe --state "$state_dir" --kind unsigned
./aauth-callchain status --state "$state_dir"
./aauth-callchain call --state "$state_dir"
./aauth-callchain status --state "$state_dir"
```

`init`, `status`, `call` and `probe` each print one JSON line. `status` reports `metadata_requests`,
`jwks_requests` and `consequence_count` for each role, plus a top-level
`consequence_count` copied from Inventory. That top-level value is "the count"
below.

A refusal is the expected result of a probe: `probe` exits `0` and reports
`status: refused`, the HTTP status, and `signature_error`, the JSON field holding
the response's `Signature-Error` header value (possibly empty). It exits
nonzero only when it could not get that refusal. Read the JSON, not the exit
code, to see what happened.

The unsigned probe reports `refused` with HTTP `401`, and the count stays zero.
The authorized call reports `completed`, `person-at-orders`,
`person-at-inventory`, `inventory.reserve` and `consequence_count: 1`. Its
`intermediary_key` must equal the `intermediary_key` printed by `init`; compare
the two strings. `downstream_person_exp` and `downstream_auth_exp` must not
exceed `upstream_exp`. Nonzero metadata and JWKS request counts in `status`
show that discovery crossed the TLS sockets.

The original Auth token lasts 20 seconds. Wait until the call's `upstream_exp`
plus one second, or simply wait 21 seconds after the successful call, then
present that exact retained credential with a fresh HTTP signature:

```sh
sleep 21
./aauth-callchain probe --state "$state_dir" --kind expired
./aauth-callchain status --state "$state_dir"
```

The probe reports HTTP `401` and `signature_error: error=expired_jwt` from
Orders; the count stays one. Before sending, the probe command itself verifies
that the retained credential has expired. That check discovers the Person
Server's metadata and signing keys, so the Person Server's request counts rise
even though no action occurs. Calling the expired probe too early exits nonzero
with a wait instruction and sends no application request.

Stop the processes before deleting their private state. Each role shuts down
on the termination signal and prints nothing:

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
chaining, sub-agent chaining, repeated hops and cascade are outside this
walkthrough's pinned commit.

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
