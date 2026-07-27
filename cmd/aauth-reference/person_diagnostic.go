package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const personDiagnosticFormat = "aauth.reference.person-diagnostic.v0"

type personDiagnostic struct {
	Schema             string `json:"schema"`
	Status             string `json:"status"`
	Identifier         string `json:"identifier"`
	Listen             string `json:"listen"`
	KeyID              string `json:"key_id"`
	KeyThumbprint      string `json:"key_thumbprint"`
	TLSNotBefore       string `json:"tls_not_before"`
	TLSNotAfter        string `json:"tls_not_after"`
	GovernanceState    string `json:"governance_state"`
	TrustedIssuerCount int    `json:"trusted_issuer_count"`
	AllowedActionCount int    `json:"allowed_action_count"`
	AllowedScopeCount  int    `json:"allowed_scope_count"`
}

func runPersonDiagnosis(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("diagnose person", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	profilePath := flags.String("profile", "", "protected person-server profile")
	if err := flags.Parse(args); err != nil ||
		flags.NArg() != 0 ||
		strings.TrimSpace(*profilePath) != *profilePath ||
		*profilePath == "" {
		writeUsage(stderr)
		return 2
	}
	deployment, err := loadPersonDeployment(*profilePath)
	if err != nil {
		fmt.Fprintf(stderr, "aauth-reference: person diagnosis failed: %v\n", err)
		return 1
	}
	defer deployment.close()
	thumbprint, err := deployment.publicKey.Thumbprint()
	if err != nil {
		fmt.Fprintln(stderr, "aauth-reference: person diagnosis failed: signing identity")
		return 1
	}
	governanceState := "new"
	if _, err := os.Lstat(deployment.profile.GovernanceFile); err == nil {
		governanceState = "loaded"
	} else if !os.IsNotExist(err) {
		fmt.Fprintln(stderr, "aauth-reference: person diagnosis failed: governance custody")
		return 1
	}
	body, err := json.Marshal(personDiagnostic{
		Schema:             personDiagnosticFormat,
		Status:             "valid",
		Identifier:         deployment.profile.Identifier,
		Listen:             deployment.profile.Listen,
		KeyID:              deployment.profile.KeyID,
		KeyThumbprint:      thumbprint,
		TLSNotBefore:       deployment.tlsLeaf.NotBefore.UTC().Format(time.RFC3339),
		TLSNotAfter:        deployment.tlsLeaf.NotAfter.UTC().Format(time.RFC3339),
		GovernanceState:    governanceState,
		TrustedIssuerCount: len(deployment.profile.TrustedKeys),
		AllowedActionCount: len(deployment.profile.AllowedActions),
		AllowedScopeCount:  len(deployment.profile.AllowedScopes),
	})
	if err != nil {
		fmt.Fprintln(stderr, "aauth-reference: person diagnosis failed: encode result")
		return 1
	}
	if _, err := fmt.Fprintln(stdout, string(body)); err != nil {
		fmt.Fprintln(stderr, "aauth-reference: person diagnosis failed: publish result")
		return 1
	}
	return 0
}
