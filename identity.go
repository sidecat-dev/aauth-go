package aauth

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

var (
	agentLocalPattern  = regexp.MustCompile(`^[a-z0-9._+\-]+$`)
	domainLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

// ValidateServerIdentifier enforces the AAuth scheme-and-host identifier form.
func ValidateServerIdentifier(identifier string) error {
	if identifier == "" {
		return errors.New("aauth: server identifier is required")
	}
	if strings.Contains(identifier, "#") {
		return errors.New("aauth: server identifier must not contain a fragment")
	}
	parsed, err := url.Parse(identifier)
	if err != nil {
		return fmt.Errorf("aauth: parse server identifier: %w", err)
	}
	if parsed.Scheme != "https" {
		return errors.New("aauth: server identifier must use https")
	}
	if parsed.User != nil || parsed.Port() != "" || parsed.Path != "" || parsed.RawPath != "" ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return errors.New("aauth: server identifier must contain only https scheme and host")
	}
	host := parsed.Hostname()
	if host == "" || host != parsed.Host || host != strings.ToLower(host) {
		return errors.New("aauth: server identifier host must be lowercase without a port")
	}
	if net.ParseIP(host) != nil {
		return errors.New("aauth: server identifier host must be a domain name")
	}
	if err := validateDomain(host); err != nil {
		return fmt.Errorf("aauth: server identifier host: %w", err)
	}
	return nil
}

// ValidateEndpoint validates an HTTPS protocol endpoint while allowing paths.
func ValidateEndpoint(endpoint string) error {
	if strings.Contains(endpoint, "#") {
		return errors.New("aauth: endpoint must not contain a fragment")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("aauth: parse endpoint: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		return errors.New("aauth: endpoint must be an absolute https URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return errors.New("aauth: endpoint must not contain userinfo, query, or fragment")
	}
	if parsed.Hostname() != strings.ToLower(parsed.Hostname()) {
		return errors.New("aauth: endpoint host must be lowercase")
	}
	return nil
}

// ValidateAgentIdentifier validates the AAuth URI identifier grammar.
func ValidateAgentIdentifier(identifier string) error {
	if !strings.HasPrefix(identifier, "aauth:") {
		return errors.New("aauth: agent identifier must use the aauth scheme")
	}
	value := strings.TrimPrefix(identifier, "aauth:")
	local, domain, ok := strings.Cut(value, "@")
	if !ok || local == "" || domain == "" || strings.Contains(domain, "@") {
		return errors.New("aauth: agent identifier must have local@domain")
	}
	if len(local) > 255 || !agentLocalPattern.MatchString(local) {
		return errors.New("aauth: agent identifier local part is invalid")
	}
	if err := validateDomain(domain); err != nil {
		return fmt.Errorf("aauth: agent identifier domain: %w", err)
	}
	return nil
}

// ValidateAgentIssuer requires an Agent identifier's domain to match its
// Agent Provider issuer.
func ValidateAgentIssuer(agent, issuer string) error {
	return validateAgentIssuerDomain(agent, issuer)
}

// ValidateAgentRelationship enforces top-level and single-level sub-agent
// naming alongside the authoritative parent_agent relationship.
func ValidateAgentRelationship(agent, parent string) error {
	agentLocal, agentDomain, err := agentIdentifierParts(agent)
	if err != nil {
		return err
	}
	if parent == "" {
		if strings.Contains(agentLocal, "+") {
			return errors.New("aauth: top-level agent local part must not contain +")
		}
		return nil
	}
	parentLocal, parentDomain, err := agentIdentifierParts(parent)
	if err != nil {
		return fmt.Errorf("aauth: parent agent: %w", err)
	}
	if strings.Contains(parentLocal, "+") {
		return errors.New("aauth: a sub-agent cannot be the parent of another sub-agent")
	}
	if agentDomain != parentDomain {
		return errors.New("aauth: sub-agent and parent must use the same domain")
	}
	discriminator := strings.TrimPrefix(agentLocal, parentLocal+"+")
	if discriminator == agentLocal || discriminator == "" || strings.Contains(discriminator, "+") {
		return errors.New("aauth: sub-agent local part must be parent local plus one non-empty discriminator")
	}
	return nil
}

func agentIdentifierParts(identifier string) (string, string, error) {
	if err := ValidateAgentIdentifier(identifier); err != nil {
		return "", "", err
	}
	value := strings.TrimPrefix(identifier, "aauth:")
	local, domain, _ := strings.Cut(value, "@")
	return local, domain, nil
}

func validateDomain(domain string) error {
	if domain == "" || len(domain) > 253 || domain != strings.ToLower(domain) {
		return errors.New("domain must be non-empty lowercase ASCII")
	}
	for _, label := range strings.Split(domain, ".") {
		if !domainLabelPattern.MatchString(label) {
			return fmt.Errorf("invalid domain label %q", label)
		}
	}
	return nil
}
