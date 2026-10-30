// Package storetest provides reusable contracts for Resource stores.
// RunSession and RunDeferredSession check Resource-managed session state;
// RunHeldInvocation checks deferred application-execution custody, and
// RunHeldBudget the Rechallenge of a held Budget refusal;
// RunR3Document checks immutable document retention; RunBudget checks atomic
// hard-cap charging; RunAuthTokenStatus checks observed and revoked Auth-token
// state; and RunAgentTokenRevocation checks direct Agent-token revocation.
// Applications still need backend restart and failure-injection tests.
package storetest
