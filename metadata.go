package aauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// Metadata holds the members every AAuth metadata document defines the same
// way (Core, Metadata Documents). Name and Description are untrusted display
// text; Description is Markdown and must be sanitized before rendering.
// AcceptSignatureAlgs, when present, is exactly the set of JWS algorithms the
// server's verifier accepts at every endpoint.
type Metadata struct {
	Issuer              string   `json:"issuer"`
	JWKSURI             string   `json:"jwks_uri,omitempty"`
	AcceptSignatureAlgs []string `json:"accept_signature_algs,omitempty"`
	Name                string   `json:"name,omitempty"`
	Description         string   `json:"description,omitempty"`
	LogoURI             string   `json:"logo_uri,omitempty"`
	LogoDarkURI         string   `json:"logo_dark_uri,omitempty"`
	DocumentationURI    string   `json:"documentation_uri,omitempty"`
	TOSURI              string   `json:"tos_uri,omitempty"`
	PolicyURI           string   `json:"policy_uri,omitempty"`
}

// AgentProviderMetadata is /.well-known/aauth-agent.json (Core, Agent
// Provider Metadata). EventEndpoint is the Events companion's member.
type AgentProviderMetadata struct {
	Metadata
	CallbackEndpoint         string `json:"callback_endpoint,omitempty"`
	EventEndpoint            string `json:"event_endpoint,omitempty"`
	LocalhostCallbackAllowed bool   `json:"localhost_callback_allowed,omitempty"`
}

// PersonServerMetadata is /.well-known/aauth-person.json (Core, Person Server
// Metadata). AuthTokenEndpoint and PersonTokenEndpoint are required; an empty
// optional endpoint means the Person Server does not offer it.
type PersonServerMetadata struct {
	Metadata
	AuthTokenEndpoint      string   `json:"auth_token_endpoint"`
	PersonTokenEndpoint    string   `json:"person_token_endpoint"`
	MissionEndpoint        string   `json:"mission_endpoint,omitempty"`
	PermissionEndpoint     string   `json:"permission_endpoint,omitempty"`
	AuditEndpoint          string   `json:"audit_endpoint,omitempty"`
	InteractionEndpoint    string   `json:"interaction_endpoint,omitempty"`
	MissionControlEndpoint string   `json:"mission_control_endpoint,omitempty"`
	RevocationEndpoint     string   `json:"revocation_endpoint,omitempty"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	ClaimsSupported        []string `json:"claims_supported,omitempty"`
}

// AccessServerMetadata is /.well-known/aauth-access.json (Core, Access Server
// Metadata).
type AccessServerMetadata struct {
	Metadata
	AuthTokenEndpoint  string `json:"auth_token_endpoint"`
	RevocationEndpoint string `json:"revocation_endpoint,omitempty"`
}

// ResourceMetadata is /.well-known/aauth-resource.json (Core, Resource
// Metadata). JWKSURI is optional here: a Resource that only verifies Agent
// signatures has no keys to publish. AccessMode is advisory, and an empty one
// means agent-token. SignatureWindow is nil when the Resource uses the default
// of 60 seconds. R3Vocabularies is the R3 companion's member, and BudgetUnits
// and UsageEndpoint are the Budgets companion's; BudgetUnits is kept as its
// exact JSON, which the budgets package parses.
type ResourceMetadata struct {
	Metadata
	AccessMode                    string            `json:"access_mode,omitempty"`
	AuthorizationEndpoint         string            `json:"authorization_endpoint,omitempty"`
	ScopeDescriptions             map[string]string `json:"scope_descriptions,omitempty"`
	SignatureWindow               *int64            `json:"signature_window,omitempty"`
	AdditionalSignatureComponents []string          `json:"additional_signature_components,omitempty"`
	RevocationEndpoint            string            `json:"revocation_endpoint,omitempty"`
	R3Vocabularies                map[string]string `json:"r3_vocabularies,omitempty"`
	BudgetUnits                   json.RawMessage   `json:"budget_units,omitempty"`
	UsageEndpoint                 string            `json:"usage_endpoint,omitempty"`
}

// DecodeAgentProviderMetadata verifies one exact aauth-agent.json document
// fetched from issuer. See DecodePersonServerMetadata for the shared checks.
func DecodeAgentProviderMetadata(exact []byte, issuer string) (AgentProviderMetadata, error) {
	var metadata AgentProviderMetadata
	if err := decodeMetadata(exact, issuer, AgentDiscoveryDocument, &metadata, &metadata.Metadata); err != nil {
		return AgentProviderMetadata{}, err
	}
	if metadata.JWKSURI == "" {
		return AgentProviderMetadata{}, metadataMemberRequired(AgentDiscoveryDocument, "jwks_uri")
	}
	if err := validateMetadataEndpoints(AgentDiscoveryDocument, []metadataMember{{"callback_endpoint", metadata.CallbackEndpoint}}); err != nil {
		return AgentProviderMetadata{}, err
	}
	if err := validateMetadataURLs(AgentDiscoveryDocument, []metadataMember{{"event_endpoint", metadata.EventEndpoint}}); err != nil {
		return AgentProviderMetadata{}, err
	}
	return metadata, nil
}

// DecodePersonServerMetadata verifies one exact aauth-person.json document
// fetched from issuer: one unambiguous JSON object, an issuer member equal to
// issuer byte for byte (a missing one is signaturekey error issuer_missing and
// a different one issuer_mismatch, as Core, Metadata Documents requires), the
// required members present, https for jwks_uri and the display URIs, and
// https without query or fragment for the token and mission endpoints (Core,
// Endpoint and Other URLs). Unknown members are ignored.
func DecodePersonServerMetadata(exact []byte, issuer string) (PersonServerMetadata, error) {
	var metadata PersonServerMetadata
	if err := decodeMetadata(exact, issuer, PersonDiscoveryDocument, &metadata, &metadata.Metadata); err != nil {
		return PersonServerMetadata{}, err
	}
	for _, member := range []metadataMember{
		{"jwks_uri", metadata.JWKSURI}, {"auth_token_endpoint", metadata.AuthTokenEndpoint},
		{"person_token_endpoint", metadata.PersonTokenEndpoint},
	} {
		if member.value == "" {
			return PersonServerMetadata{}, metadataMemberRequired(PersonDiscoveryDocument, member.name)
		}
	}
	if err := validateMetadataEndpoints(PersonDiscoveryDocument, []metadataMember{
		{"auth_token_endpoint", metadata.AuthTokenEndpoint}, {"person_token_endpoint", metadata.PersonTokenEndpoint},
		{"mission_endpoint", metadata.MissionEndpoint},
	}); err != nil {
		return PersonServerMetadata{}, err
	}
	return metadata, nil
}

// DecodeAccessServerMetadata verifies one exact aauth-access.json document
// fetched from issuer. See DecodePersonServerMetadata for the shared checks.
func DecodeAccessServerMetadata(exact []byte, issuer string) (AccessServerMetadata, error) {
	var metadata AccessServerMetadata
	if err := decodeMetadata(exact, issuer, AccessDiscoveryDocument, &metadata, &metadata.Metadata); err != nil {
		return AccessServerMetadata{}, err
	}
	for _, member := range []metadataMember{
		{"jwks_uri", metadata.JWKSURI}, {"auth_token_endpoint", metadata.AuthTokenEndpoint},
	} {
		if member.value == "" {
			return AccessServerMetadata{}, metadataMemberRequired(AccessDiscoveryDocument, member.name)
		}
	}
	if err := validateMetadataEndpoints(AccessDiscoveryDocument, []metadataMember{{"auth_token_endpoint", metadata.AuthTokenEndpoint}}); err != nil {
		return AccessServerMetadata{}, err
	}
	return metadata, nil
}

// DecodeResourceMetadata verifies one exact aauth-resource.json document
// fetched from issuer. See DecodePersonServerMetadata for the shared checks;
// authorization_endpoint and usage_endpoint are endpoint URLs, and
// signature_window must be positive.
func DecodeResourceMetadata(exact []byte, issuer string) (ResourceMetadata, error) {
	var metadata ResourceMetadata
	if err := decodeMetadata(exact, issuer, ResourceDiscoveryDocument, &metadata, &metadata.Metadata); err != nil {
		return ResourceMetadata{}, err
	}
	if err := validateMetadataEndpoints(ResourceDiscoveryDocument, []metadataMember{
		{"authorization_endpoint", metadata.AuthorizationEndpoint}, {"usage_endpoint", metadata.UsageEndpoint},
	}); err != nil {
		return ResourceMetadata{}, err
	}
	if metadata.SignatureWindow != nil && *metadata.SignatureWindow <= 0 {
		return ResourceMetadata{}, fmt.Errorf("aauth: %s signature_window must be a positive integer", ResourceDiscoveryDocument)
	}
	return metadata, nil
}

// decodeMetadata decodes exact into destination and checks the members every
// document shares; common is the destination's embedded Metadata.
func decodeMetadata(exact []byte, issuer, document string, destination any, common *Metadata) error {
	if err := jsonstrict.RejectCaseVariants(exact, destination); err != nil {
		return fmt.Errorf("aauth: decode %s: %w", document, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(exact))
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("aauth: decode %s: %w", document, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("aauth: %s must contain one JSON value", document)
	}
	if common.Issuer == "" {
		return signaturekey.NewError(signaturekey.ErrorIssuerMissing, fmt.Errorf("aauth: %s has no issuer", document))
	}
	if common.Issuer != issuer {
		return signaturekey.NewError(signaturekey.ErrorIssuerMismatch,
			fmt.Errorf("aauth: %s issuer %q does not match %q", document, common.Issuer, issuer))
	}
	if err := ValidateServerIdentifier(common.Issuer); err != nil {
		return fmt.Errorf("aauth: %s issuer: %w", document, err)
	}
	return validateMetadataURLs(document, []metadataMember{
		{"jwks_uri", common.JWKSURI}, {"logo_uri", common.LogoURI}, {"logo_dark_uri", common.LogoDarkURI},
		{"documentation_uri", common.DocumentationURI}, {"tos_uri", common.TOSURI}, {"policy_uri", common.PolicyURI},
	})
}

// validateMetadataEndpoints checks the endpoint members Core requires to be
// https without a query or fragment; an empty value is absent.
func validateMetadataEndpoints(document string, endpoints []metadataMember) error {
	for _, member := range endpoints {
		if member.value == "" {
			continue
		}
		if err := ValidateEndpoint(member.value); err != nil {
			return fmt.Errorf("aauth: %s %s: %w", document, member.name, err)
		}
	}
	return nil
}

// validateMetadataURLs checks members that must be absolute https URLs; an
// empty value is absent.
func validateMetadataURLs(document string, values []metadataMember) error {
	for _, member := range values {
		if member.value == "" {
			continue
		}
		if err := ValidateHTTPSURL(member.value); err != nil {
			return fmt.Errorf("aauth: %s %s: %w", document, member.name, err)
		}
	}
	return nil
}

// metadataMember is one named member value, checked in document order.
type metadataMember struct{ name, value string }

func metadataMemberRequired(document, member string) error {
	return fmt.Errorf("aauth: %s %s is required", document, member)
}
