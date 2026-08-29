package r3

import "time"

// IssuanceAudit is the exact R3 authorization context retained atomically with
// one direct auth-token issuance.
type IssuanceAudit struct {
	AccessServer    string    `json:"access_server"`
	PersonServer    string    `json:"person_server"`
	Subject         string    `json:"subject"`
	Agent           string    `json:"agent"`
	ParentAgent     string    `json:"parent_agent,omitempty"`
	AgentJKT        string    `json:"agent_jkt"`
	Resource        string    `json:"resource"`
	ResourceTokenID string    `json:"resource_token_id"`
	AuthTokenID     string    `json:"auth_token_id"`
	URI             string    `json:"r3_uri"`
	Digest          string    `json:"r3_s256"`
	IssuedAt        time.Time `json:"issued_at"`
}
