# AAuth for Go: documentation

Start with [Get started](getting-started.md): it runs an agent calling an API
over TLS on your machine, and walks through the code. Then read
[How AAuth works](how-aauth-works.md) for the parties, the tokens and the ways
an API can decide who gets in.

## Roles

Each guide says what the role does, shows the flow, and shows the code that
sets it up. The code on these pages is quoted from the repository's compiled
examples, and a test (`internal/docscheck`) fails if a quote stops matching.

| Guide | Package | For |
| --- | --- | --- |
| [Agent](roles/agent.md) | `agent` | an HTTP client that calls APIs for a person |
| [Agent Provider](roles/agent-provider.md) | `agentprovider` | vouching for agents with Agent tokens |
| [Resource](roles/resource.md) | `resource` | an API that checks who is calling |
| [Person Server](roles/person-server.md) | `personserver` | knowing which person an agent acts for, and what they allow |
| [Access Server](roles/access-server.md) | `accessserver` | an API that decides access by its own rules |
| [Supervision Server](roles/supervision-server.md) | `supervisionserver` | approving or refusing an agent's requests for the person |

## Features

| Guide | What it adds | Defined in |
| --- | --- | --- |
| [Call chaining](features/call-chaining.md) | an API calling another API for the same person | core protocol |
| [Missions](features/missions.md) | a task the person approves up front; tokens issued for it are checked against it | core protocol |
| [R3](features/r3.md) | approving named operations, such as MCP tools, instead of broad scopes | `draft-hardt-aauth-r3` |
| [Budgets](features/budgets.md) | a cap on what an agent may spend at an API | `draft-hardt-aauth-budgets` |
| [Events](features/events.md) | an API notifying an agent later, through its Agent Provider | `draft-hardt-aauth-events` |
| [Supervision](features/supervision.md) | what happens to each request a supervision server decides | `draft-hardt-aauth-supervision` |

## Reference

- [Errors](errors.md): the refusals the servers send, and what the caller does
  about each.
- [USE-IN-YOUR-SERVICE.md](../USE-IN-YOUR-SERVICE.md): the full reference for
  running each role in a service.
- [CONFORMANCE.md](../CONFORMANCE.md): what the library does and does not do,
  and the tests that show it.
- [INTERPRETATIONS.md](../INTERPRETATIONS.md): the choices made where a draft
  leaves room.
- [SPECIFICATIONS.md](../SPECIFICATIONS.md): the draft versions implemented.
- [GLOSSARY.md](../GLOSSARY.md): the terms, token claims and type names, one
  line each.
- [PROTOCOL.md](../PROTOCOL.md): how the drafts fit together into roles,
  values and journeys.
- [JOURNEYS.md](../JOURNEYS.md): every runnable flow, with its tests.
- [ARCHITECTURE.md](../ARCHITECTURE.md): the packages, what each depends on,
  and where state lives.
- [SECURITY.md](../SECURITY.md): what your service is responsible for.

Package documentation is in the code: run `go doc` on a package, for example
`go doc gitlab.com/sidecat-dev/aauth-go/resource`.

## Examples

Every example runs in one process on your machine, with no account and no
outside service. Run each from a clone of the repository.

| Command | Shows |
| --- | --- |
| `go run ./example/gettingstarted` | an agent calling an API over TLS, with its Agent token |
| `go run ./example/verifyagent` | the same check in one process, with no network |
| `go run ./example/agentidentity` | the Agent client calling a Resource with its Agent token |
| `go run ./example/threeparty` | a Person Server's consent before the Resource answers |
| `go run ./example/fourparty` | an Access Server's decision, with and without a mission, and with R3 |
| `go run ./example/federatedpayment` | an Access Server asking for payment and approval while the agent waits |
| `go run ./example/psconsent` | a Person Server waiting for the person's consent, with a question to the agent first |
| `go run ./example/callchaining` | one API calling another for the same person |
| `go run ./example/mission` | a mission proposed, approved, used and completed |
| `go run ./example/r3threeparty` | approving one named MCP operation and withholding another |
| `go run ./example/budget` | a spending cap: charged, refused when short, and topped up |
| `go run ./example/events` | an API sending events to an agent through its Agent Provider |
| `go run ./example/supervision` | one person, two agents, two supervision servers |
| `go run ./example/subagent` | a parent agent getting credentials for a sub-agent |
| `go run ./example/revocation` | revoking tokens, and recovering with a fresh Person token |
| `go run ./example/bootstrap` | an Agent Provider enrolling an agent's durable key and refreshing its Agent token, two-key and single-key |
| `go run ./example/selfhosted` | a domain that is its own Agent Provider, issuing its agents' tokens |

The `walkthrough/` directories run the roles as separate TLS processes with
state on disk. Each is its own Go module, pinned to an older commit of this
library; read its README before you copy from it.
