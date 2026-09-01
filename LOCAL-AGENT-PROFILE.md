# Local Agent profile

This profile composes a self-hosted Agent, a local Person Server, and a
Resource into the smallest useful local deployment. It is an implementation
profile, not an additional AAuth specification.

## Journey

1. The Agent publishes ordinary Agent Provider metadata and JWKS at its own
   origin.
2. It self-issues a short-lived Agent token whose confirmation key is the same
   user-controlled key.
3. The token names a separately identified Person Server. The Agent asks that
   server for permission to perform one local action.
4. The application acts only after the Agent receives a typed grant.
5. The same Agent token and proof key can authenticate an ordinary direct
   Agent-identity call to a Resource.

Run the complete in-process composition:

```sh
go run ./example/selfhosted
```

The example uses normal signed HTTP requests and the exported Agent Provider,
Agent, Person Server, and Resource handlers. Its logical transport keeps the
example in one process; it does not bypass protocol verification.

## Application boundary

An application supplies the Agent key, Person Server policy, admitted
endpoints, durable stores, and the code that performs an approved local action.
The example uses memory stores and fixed keys and time, so it does not prove
restart recovery, operating-system key protection, TLS deployment, or user
authentication. Use the applicable public `storetest` contracts for durable
adapters.

For enrollment, account-hosted review, service connectors, and Budget-limited
operations, continue with [HOSTED-SERVICE-PROFILE.md](HOSTED-SERVICE-PROFILE.md).
