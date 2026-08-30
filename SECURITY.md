# Security policy

## Report a vulnerability privately

Do not open a public issue for a vulnerability or suspected credential leak.
Use the repository host's private vulnerability-reporting channel when it is
available. Otherwise, contact a maintainer through a verified private address
published by the project.

Include:

- the affected commit or release;
- the relevant specification section;
- the security impact and required preconditions;
- a minimal reproducer or test;
- whether the report contains sensitive tokens, keys, or personal data.

Do not send live credentials or private keys. Use synthetic material whenever
possible.

The maintainers will confirm receipt, reproduce the issue, and coordinate the
fix and disclosure with the reporter. A public specification ambiguity that
does not reveal an exploitable implementation defect may be reported through
the normal issue tracker.

## Deployment responsibilities

URL admission is not a network sandbox. The HTTP key resolver validates
metadata, issuer identity, JWKS documents, and response bounds and rejects
redirects, but the caller-supplied transport must resolve and pin the admitted
host, reject forbidden addresses, and prevent DNS rebinding. Give every
outbound operation a finite context and apply the same destination controls to
Agent and Person Server clients.

Keep signing keys outside this module and use HTTPS at the process boundary. A
valid signature authenticates protocol input; it does not replace application
authorization policy. Durable store implementations contain sensitive tokens,
requests, and decisions and must preserve the exact integrity,
confidentiality, and atomicity required by their public contracts.

When a pending result outlives a signing-key rotation, the deployment must keep
the required prior verification key resolvable until that result is delivered
or expires. The built-in role JWKS handlers publish only their active key.

## Supported code

The project is under active development. Security fixes target the current
development line. A release support policy will be published when supported
releases exist.
