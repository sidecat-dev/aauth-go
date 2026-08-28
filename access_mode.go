package aauth

// AccessMode is a credential-flow value from the current AAuth registry. The
// reference Resource currently implements explicit auth-token mode only; the
// other constants let metadata and host integrations represent the registry
// without implying handler support.
type AccessMode string

const (
	AccessModeAgentToken   AccessMode = "agent-token"
	AccessModePersonToken  AccessMode = "person-token"
	AccessModeSessionToken AccessMode = "session-token"
	AccessModeAuthToken    AccessMode = "auth-token"
)
