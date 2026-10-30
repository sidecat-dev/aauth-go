// Package storetest provides reusable contracts for Agent Provider stores.
// RunEnrollment checks enrollment identity and refresh recovery, and
// RunEventInbox checks the Events inbox: subscription binding, the max_uses
// bound, exact replay, and unchanged retention of accepted deliveries.
// RunEventInboxReader checks the inbox's read path to its Agents.
package storetest
