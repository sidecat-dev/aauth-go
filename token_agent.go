package aauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"aauth-go/jose"
	"aauth-go/signaturekey"
)

// AgentTokenRequest is the issuer-validated input to agent-token creation.
type AgentTokenRequest struct {
	Agent            string
	PersonServer     string
	ParentAgent      string
	PublicKey        jose.JWK
	NotBefore        time.Time
	Lifetime         time.Duration
	AdditionalClaims map[string]json.RawMessage
}

// AgentTokenClaims are the Core claims of an aa-agent+jwt.
type AgentTokenClaims struct {
	Issuer           string                     `json:"iss"`
	DWK              string                     `json:"dwk"`
	Subject          string                     `json:"sub"`
	JTI              string                     `json:"jti"`
	Confirmation     Confirmation               `json:"cnf"`
	IssuedAt         int64                      `json:"iat"`
	ExpiresAt        int64                      `json:"exp"`
	NotBefore        int64                      `json:"nbf,omitempty"`
	PersonServer     string                     `json:"ps,omitempty"`
	ParentAgent      string                     `json:"parent_agent,omitempty"`
	AdditionalClaims map[string]json.RawMessage `json:"-"`
}

var agentTokenClaimNames = map[string]struct{}{
	"iss": {}, "dwk": {}, "sub": {}, "jti": {}, "cnf": {}, "iat": {},
	"exp": {}, "ps": {}, "parent_agent": {},
	"nbf": {},
}

// MintAgentToken creates an agent token with the supplied issuer key.
func MintAgentToken(issuer string, key jose.SigningKey, request AgentTokenRequest, now time.Time, jti string) (string, error) {
	notBefore := int64(0)
	if !request.NotBefore.IsZero() {
		notBefore = request.NotBefore.Unix()
	}
	claims := AgentTokenClaims{
		Issuer: issuer, DWK: AgentDiscoveryDocument, Subject: request.Agent, JTI: jti,
		Confirmation: Confirmation{JWK: request.PublicKey}, IssuedAt: now.Unix(),
		ExpiresAt: now.Add(request.Lifetime).Unix(), NotBefore: notBefore, PersonServer: request.PersonServer,
		ParentAgent: request.ParentAgent,
	}
	if err := validateAgentClaims(claims, time.Time{}); err != nil {
		return "", err
	}
	additional := request.AdditionalClaims
	claims.AdditionalClaims = nil
	payload, _, err := marshalTokenClaims("agent-token", claims, additional, agentTokenClaimNames)
	if err != nil {
		return "", err
	}
	return mintTokenPayload(key, AgentTokenType, payload)
}

func (claims *AgentTokenClaims) setTokenMembers(members map[string]json.RawMessage) {
	claims.AdditionalClaims = additionalTokenClaims(members, agentTokenClaimNames)
}

// VerifyAgentToken verifies compact-token trust and claims. The caller must
// still bind the result to the request key and receiving operation.
func VerifyAgentToken(ctx context.Context, compact string, resolver signaturekey.KeyResolver, clock Clock) (AgentTokenClaims, error) {
	var claims AgentTokenClaims
	return verifyCoreToken(
		ctx, compact, AgentTokenType, []string{AgentDiscoveryDocument}, resolver, clock,
		&claims,
		func(value AgentTokenClaims) (string, string) { return value.Issuer, value.DWK },
		nil,
		validateAgentClaims,
	)
}

func validateAgentClaims(claims AgentTokenClaims, now time.Time) error {
	if err := ValidateServerIdentifier(claims.Issuer); err != nil {
		return fmt.Errorf("aauth: agent-token issuer: %w", err)
	}
	if claims.DWK != AgentDiscoveryDocument {
		return errors.New("aauth: agent-token dwk is invalid")
	}
	if err := ValidateAgentIdentifier(claims.Subject); err != nil {
		return fmt.Errorf("aauth: agent-token subject: %w", err)
	}
	if err := validateAgentIssuerDomain(claims.Subject, claims.Issuer); err != nil {
		return fmt.Errorf("aauth: agent-token subject: %w", err)
	}
	if claims.JTI == "" {
		return errors.New("aauth: agent-token jti is required")
	}
	if err := validateTimes(claims.IssuedAt, claims.ExpiresAt, claims.NotBefore, now); err != nil {
		return fmt.Errorf("aauth: agent-token: %w", err)
	}
	if _, err := claims.Confirmation.JWK.PublicKey(); err != nil {
		return tokenKeyValidationError("agent-token cnf.jwk", err)
	}
	if claims.PersonServer != "" {
		if err := ValidateServerIdentifier(claims.PersonServer); err != nil {
			return fmt.Errorf("aauth: agent-token ps: %w", err)
		}
	}
	if claims.ParentAgent != "" {
		if err := ValidateAgentIdentifier(claims.ParentAgent); err != nil {
			return fmt.Errorf("aauth: agent-token parent_agent: %w", err)
		}
	}
	if err := ValidateAgentRelationship(claims.Subject, claims.ParentAgent); err != nil {
		return fmt.Errorf("aauth: agent-token relationship: %w", err)
	}
	return nil
}

func validateAgentIssuerDomain(agent string, issuer string) error {
	_, agentDomain, err := agentIdentifierParts(agent)
	if err != nil {
		return err
	}
	if err := ValidateServerIdentifier(issuer); err != nil {
		return err
	}
	providerDomain := strings.TrimPrefix(issuer, "https://")
	if agentDomain != providerDomain {
		return fmt.Errorf("agent identifier domain %q does not match issuer domain %q", agentDomain, providerDomain)
	}
	return nil
}
