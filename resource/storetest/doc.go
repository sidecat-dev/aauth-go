// Package storetest provides reusable contracts for Resource stores.
// RunSession and RunDeferredSession check Resource-managed session state;
// RunR3Document checks immutable document retention; RunBudget checks atomic
// hard-cap charging; and RunAgentTokenRevocation checks direct Agent-token
// revocation. Applications still need backend restart and failure-injection
// tests.
package storetest
