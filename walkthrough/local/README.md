# Local process walkthrough

This walkthrough runs one Agent and one local service as separate TLS
processes. The service contains a Person Server and a protected Resource. The
Agent:

1. asks the Person Server for permission to create one note;
2. signs the protected Resource request;
3. retains the result under a caller-selected request key;
4. returns the same result after both processes restart; and
5. refuses a new action after the Agent token is revoked.

The walkthrough is a standalone Go module. It requires the published
`aauth-go` module without a `replace` directive and imports only public
packages.

## Run it

Build the command and initialize a temporary state directory:

```sh
cd walkthrough/local
go build -o ./aauth-local .

state_dir="$(mktemp -d)"
./aauth-local init \
  --state "$state_dir" \
  --agent-address 127.0.0.1:18443 \
  --service-address 127.0.0.1:19443
```

Start the local service in one terminal:

```sh
./aauth-local service --state "$state_dir"
```

Start the Agent in a second terminal:

```sh
./aauth-local agent --state "$state_dir"
```

Run the protected action from a third terminal:

```sh
./aauth-local act --state "$state_dir" --request-key local-write-1
```

The result names the verified Agent and the one retained consequence:

```json
{"status":"completed","agent":"aauth:local@agent.local","request_key":"local-write-1","result":"note-1","replayed":false,"consequence_count":1}
```

Stop the Agent and service with `Ctrl-C`, restart both commands, and repeat the
same action. The result remains `note-1`, `consequence_count` remains `1`, and
`replayed` becomes `true`.

Revoke the active Agent token and try a new action:

```sh
./aauth-local revoke --state "$state_dir"
./aauth-local act --state "$state_dir" --request-key local-write-2
```

The second command exits unsuccessfully with `invalid_agent_token`. Confirm
that the service still retained only one consequence:

```sh
./aauth-local status --state "$state_dir"
```

## Verify it

The acceptance test builds the command, starts both processes, sends an
unsigned negative control, completes the signed action, restarts both
processes, verifies exact replay, revokes the credential, and confirms that no
second consequence ran. The store tests run the library's public permission
and Agent-token revocation contracts against the file adapters.

```sh
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
```

## Boundary

This is a local development walkthrough, not deployment infrastructure. It
uses generated 24-hour certificates, loopback listeners, and JSON files with
single-process ownership. The command authenticates control requests with a
generated bearer credential stored under mode `0600`; the control listener is
also bound to the configured loopback address. Delete the state directory when
finished; it contains private keys and credentials.
