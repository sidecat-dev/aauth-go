package aauth

// AccessMode is a credential-flow value from the current AAuth registry. The
// Resource package provides explicit compositions for all four Core modes.
type AccessMode string

const (
	AccessModeAgentToken   AccessMode = "agent-token"
	AccessModePersonToken  AccessMode = "person-token"
	AccessModeSessionToken AccessMode = "session-token"
	AccessModeAuthToken    AccessMode = "auth-token"
)
