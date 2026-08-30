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

## Supported code

The project is under active development. Security fixes target the current
development line. A release support policy will be published when supported
releases exist.
