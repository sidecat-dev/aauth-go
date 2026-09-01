# Hosted process walkthrough

This standalone module connects a laptop Agent to a separately hosted AAuth
service over TLS. It exercises one complete hosted-service path:

1. the Agent enrolls its durable key and obtains a short-lived Agent token;
2. a person authenticates to the hosted account and links one connector;
3. the person approves a mission for one MCP operation;
4. AAuth authorizes the operation under a fixed Budget;
5. the hosted connector performs one retained write; and
6. restart, exact replay, and Agent-token revocation preserve the result and
   prevent a later connector dispatch.

The hosted application creates and retains the connector credential. It never
appears in Agent state, an AAuth token, a command response, or the account
status response.

## Build

```sh
cd walkthrough/hosted
go build -o ./aauth-hosted .
```

The module requires a published `aauth-go` revision normally. It has no
`replace` directive and imports only public packages.

## Initialize the host

Choose an HTTPS origin whose base, `person.` and `resource.` hostnames reach
the service. For example, `https://aauth.example.test` also uses
`person.aauth.example.test` and `resource.aauth.example.test`.

```sh
host_state="$(mktemp -d)"

./aauth-hosted host-init \
  --state "$host_state" \
  --listen 0.0.0.0:18443 \
  --origin https://aauth.example.test

./aauth-hosted serve --state "$host_state"
```

`host-init` writes two files to transfer through separate trusted channels:

- `bootstrap.json` contains the walkthrough CA, one enrollment code, and the
  bounded control credential;
- `user-password` contains a generated high-entropy account password.

Both files are mode `0600`. The enrollment code binds to the first durable
Agent identity and cannot enroll another Agent.

## Connect the laptop Agent

On the laptop, build the same command and initialize separate state. Omit
`--service-address` when normal DNS and the origin's port reach the host. The
override is useful for a test host whose public DNS name maps to a specific
address and port.

```sh
agent_state="$(mktemp -d)"

./aauth-hosted agent-init \
  --state "$agent_state" \
  --bootstrap ./bootstrap.json \
  --service-address HOST_IP:18443

./aauth-hosted connect --state "$agent_state"
./aauth-hosted login \
  --state "$agent_state" \
  --email person@example.test \
  --password-file ./user-password
./aauth-hosted link --state "$agent_state" --account records-primary
./aauth-hosted approve --state "$agent_state"
./aauth-hosted act --state "$agent_state" --request-key hosted-write-1
```

The action reports `record-1`, one connector call, and a zero Budget
remainder. Repeating the same request key returns the same result.

Restart `serve` around the same host state and repeat the action. The automated
acceptance test also removes only the Agent's final response cache before the
retry; the retained authorization, Budget charge, and connector result still
recover without a second connector consequence.

Revoke the enrollment and issued Agent token, then try a new request:

```sh
./aauth-hosted revoke --state "$agent_state"
./aauth-hosted act --state "$agent_state" --request-key hosted-write-2
```

The second command refuses `invalid_agent_token` before connector dispatch.

## Verify

```sh
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
```

The acceptance tests run separate TLS processes and restart the hosted
process. Public store contracts cover enrollment, mission lifecycle, atomic
mission-plus-R3 issuance, R3 documents, R3 issuance, and Budget charging.

## Boundary

This is an executable integration walkthrough, not production hosting
infrastructure. It uses generated 24-hour certificates, a generated account
password, and single-process JSON stores with atomic file replacement. It does
not provide OAuth login, multi-process database coordination, certificate
renewal, account recovery, connector-specific OAuth, or deployment automation.
Those are host responsibilities; the AAuth protocol and public Go interfaces
used here remain the same.
