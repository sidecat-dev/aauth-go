// Package storetest provides reusable contracts for Agent Provider stores.
// RunEnrollment checks enrollment identity and refresh recovery.
// RunEventInbox checks the Events inbox: subscription binding, the max_uses
// bound, exact replay, and unchanged retention of accepted deliveries.
// RunEventInboxReader checks the inbox's read path to its Agents.
// RunIssuedAgentTokens checks the record of issued Agent tokens that
// RevocationClient.RevokeAgent reads.
package storetest
