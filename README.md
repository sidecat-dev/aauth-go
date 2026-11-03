# AAuth for Go

Go packages for [AAuth](https://github.com/dickhardt/AAuth), a protocol that
tells an API which software agent is calling it and on whose behalf. The agent
signs every HTTP request with its own key. The API checks that signature and
the token sent with it. When the API needs more than the agent's identity, it
asks for a token that names the person the agent acts for and what that person
allowed.

There is a package for each party in the protocol: the agent, the Agent
Provider that vouches for it, the API (called a Resource), and the servers that
speak for the person or for the API. [How AAuth works](docs/how-aauth-works.md)
introduces them.

Each server role is an `http.Handler` that you mount in your own HTTPS server,
and each client sends its requests through the `*http.Client` you give it. Your
service decides whom to trust, authenticates people and stores state; the
packages sign, check and decide.

## Get started

You need [Go](https://go.dev/dl/) 1.25 or later. In a new directory:

```sh
go mod init example.com/hello-aauth
go get gitlab.com/sidecat-dev/aauth-go@6fcdb1e
```

Then save [the getting-started program](example/gettingstarted/main.go) as
`main.go`, and run it:

```sh
go mod tidy
go run .
```

It starts an Agent Provider and an API on loopback ports, with TLS, and has an
agent call the API. [Get started](docs/getting-started.md) walks through the
output and the code. In a clone of this repository, `go run ./example/gettingstarted`
runs the same program.

## Install

The module has no release tags: you build against a commit on `main`, named by
its hash.

```sh
go get gitlab.com/sidecat-dev/aauth-go@6fcdb1e
```

`go get` records the commit in `go.mod` as a pseudo-version,
`v0.0.0-20261102114704-6fcdb1ef51b0`. Commit `go.mod` and `go.sum` with your
code, so that every build uses the same commit. To move to a later commit, run
`go get` again with its hash.

| Package | What it does | Guide |
| --- | --- | --- |
| `agent` | Signs an agent's requests and checks the tokens it receives, one step per call | [Agent](docs/roles/agent.md) |
| `agentprovider` | Issues Agent tokens and publishes the provider's keys | [Agent Provider](docs/roles/agent-provider.md) |
| `resource` | Checks requests to an API before your handler runs | [Resource](docs/roles/resource.md) |
| `personserver` | Knows which person an agent acts for, and issues tokens that say so | [Person Server](docs/roles/person-server.md) |
| `accessserver` | Decides access for an API from the API's own rules | [Access Server](docs/roles/access-server.md) |
| `supervisionserver`, `supervision` | Approves or refuses an agent's requests for the person | [Supervision Server](docs/roles/supervision-server.md) |
| `r3` and `r3/vocab/*`, `budgets`, `events` | Operation lists, spending caps and events, used by the roles | [R3](docs/features/r3.md), [Budgets](docs/features/budgets.md), [Events](docs/features/events.md) |
| `aauth`, `signaturekey`, `jose` | Tokens, HTTP signatures and keys, used by the roles | |
| `testutil`, `*/storetest` | In-memory stores for tests, and the contracts a durable store must pass | |
| `diagnostics` | Shows the local cause of each refusal a handler sends | [Errors](docs/errors.md) |

## Documentation

- [docs/](docs/README.md): how AAuth works, a guide for each role and each
  feature, and what to do about each error.
- [USE-IN-YOUR-SERVICE.md](USE-IN-YOUR-SERVICE.md): the full reference for
  running each role in a service.
- [CONFORMANCE.md](CONFORMANCE.md): how the conformance suite measures the
  library, and what its latest run says and does not say.
- [INTERPRETATIONS.md](INTERPRETATIONS.md): the choices made where a draft
  leaves room.
- [SPECIFICATIONS.md](SPECIFICATIONS.md): the exact draft text implemented.
- [SECURITY.md](SECURITY.md): how to report a vulnerability, and what your
  service is responsible for.
- [CONTRIBUTING.md](CONTRIBUTING.md): how to change the code and run its
  tests.

## Status

The packages implement the core AAuth protocol and HTTP Signature Keys, and
the R3, Budgets, Events, Supervision and Bootstrap drafts, each described,
with its limits, in the guides under [docs/features](docs/features) and
[docs/roles](docs/roles). APIs can change from one commit to the next.

[aauth-rust](https://gitlab.com/sidecat-dev/aauth-rust) implements the same
drafts in Rust. The two are tested against each other over HTTPS, in both
directions. [INTERPRETATIONS.md](INTERPRETATIONS.md) records each choice this
library makes where a draft leaves room.

## License

MIT; see [LICENSE](LICENSE).
