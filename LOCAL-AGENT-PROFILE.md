# Local Agent profile

This profile composes a self-hosted Agent, a local Person Server, and local and
hosted Resources into a practical user-controlled deployment. It is an
implementation profile, not an additional AAuth specification.

## Journey

1. The Agent publishes ordinary Agent Provider metadata and JWKS at its own
   origin.
2. It self-issues a short-lived Agent token whose confirmation key is the same
   user-controlled key.
3. The token names a separately identified Person Server. The Agent asks that
   server for permission to perform one local action.
4. The application acts only after the Agent receives a typed grant.
5. The same Agent token and proof key authenticate an ordinary direct
   Agent-identity call to a local Resource.
6. For hosted work, the Agent self-issues a second short-lived token naming the
   hosted Person Server. The server returns an interaction URL and code rather
   than choosing an account from the request alone.
7. After authenticating the person, the host consumes that exact code and
   approves the account binding. The Agent polls explicitly and receives the
   account-bound Person token.
8. The Agent completes ordinary three-party authorization for a protected
   hosted Resource call.

Each Agent token names the Person Server responsible for that use. The Agent
identity and proof key remain stable; local and hosted person authority do not
collapse into one token or one server.

Run the complete in-process composition:

```sh
go run ./example/selfhosted
```

The example uses normal signed HTTP requests and the exported Agent Provider,
Agent, Person Server, and Resource handlers. Local and hosted roles use
distinct origins and signing keys. Its logical transport keeps the example in
one process; it does not bypass protocol verification.

## Application boundary

An application supplies the Agent key, Person Server policy, admitted
endpoints, durable stores, and the code that performs an approved local action.
The example uses memory stores and fixed keys and time, so it does not prove
restart recovery, operating-system key protection, TLS deployment, or user
authentication. Use the applicable public `storetest` contracts for durable
adapters. In particular, the hosted account-link store must pass
`personserver/storetest.RunDeferredToken`; the example runs that same contract
against its in-memory fixture.

The hosted call demonstrates the protocol boundary around account linking and
service authorization. It does not implement the browser, login session,
account database, administrative review, or connector credentials. For those
deployment capabilities and Budget-limited operations, continue with
[HOSTED-SERVICE-PROFILE.md](HOSTED-SERVICE-PROFILE.md). The command
`go run ./example/hostedservice --self-hosted` carries the same self-hosted
identity shape through reviewed mission approval, MCP R3 authorization, fixed
Budget enforcement and recovery, connector execution, and person-accepted
mission completion.
