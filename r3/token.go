package r3

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	aauth "aauth-go"
	"aauth-go/jose"
	"aauth-go/signaturekey"
)

const (
	r3URIClaim     = "r3_uri"
	r3S256Claim    = "r3_s256"
	r3GrantedClaim = "r3_granted"
	r3PerCallClaim = "r3_per_call"
)

// MintMCPResourceToken validates one exact MCP document, binds its account to
// the Core claims, derives the document reference, and mints an R3 Resource
// token. Scope is optional at this wire boundary.
func MintMCPResourceToken(
	key jose.SigningKey,
	claims aauth.ResourceTokenClaims,
	documentURI string,
	exactDocument []byte,
) (string, Reference, error) {
	document, err := ParseDocument(exactDocument)
	if err != nil {
		return "", Reference{}, fmt.Errorf("r3: resource-token document: %w", err)
	}
	if err := ValidateDocumentAccount(document, claims.Account); err != nil {
		return "", Reference{}, fmt.Errorf("r3: resource-token account: %w", err)
	}
	reference, err := NewReference(documentURI, Digest(exactDocument))
	if err != nil {
		return "", Reference{}, fmt.Errorf("r3: resource-token reference: %w", err)
	}
	additional, err := prepareMCPResourceClaims(claims.AdditionalClaims, reference)
	if err != nil {
		return "", Reference{}, err
	}
	claims.AdditionalClaims = additional
	compact, err := aauth.MintResourceTokenCore(key, claims)
	if err != nil {
		return "", Reference{}, err
	}
	return compact, reference, nil
}

// VerifyMCPResourceToken verifies Core token trust and a complete MCP R3
// reference. It validates only the signed reference syntax; it does not fetch
// or hash document bytes. Call ParseReferencedDocument after an entitled
// fetch, then ValidateDocumentAccount before policy.
func VerifyMCPResourceToken(
	ctx context.Context,
	compact string,
	resolver signaturekey.KeyResolver,
	clock aauth.Clock,
) (aauth.ResourceTokenClaims, Reference, error) {
	claims, err := aauth.VerifyResourceTokenCore(ctx, compact, resolver, clock)
	if err != nil {
		return aauth.ResourceTokenClaims{}, Reference{}, err
	}
	if err := validateMCPResourceClaims(claims.AdditionalClaims); err != nil {
		return aauth.ResourceTokenClaims{}, Reference{}, err
	}
	reference, err := referenceFromClaims(claims.AdditionalClaims)
	if err != nil {
		return aauth.ResourceTokenClaims{}, Reference{}, err
	}
	removeClaims(&claims.AdditionalClaims, r3URIClaim, r3S256Claim)
	return claims, reference, nil
}

// MintMCPDirectAuthToken mints the direct-only MCP profile after re-proving
// the supplied grant against the exact document bytes named by reference.
// It does not implement r3_per_call or Budgets composition.
func MintMCPDirectAuthToken(
	key jose.SigningKey,
	claims aauth.AuthTokenClaims,
	reference Reference,
	exactDocument []byte,
	grant Grant,
) (string, error) {
	document, err := ParseReferencedDocument(reference, exactDocument)
	if err != nil {
		return "", fmt.Errorf("r3: direct auth-token document: %w", err)
	}
	if err := ValidateDocumentAccount(document, claims.Account); err != nil {
		return "", fmt.Errorf("r3: direct auth-token account: %w", err)
	}
	grantJSON, err := json.Marshal(grant)
	if err != nil {
		return "", fmt.Errorf("r3: direct auth-token grant: %w", err)
	}
	if _, err := ParseGrant(grantJSON, document); err != nil {
		return "", fmt.Errorf("r3: direct auth-token grant does not match referenced document: %w", err)
	}
	additional, err := prepareMCPDirectAuthClaims(claims.AdditionalClaims, reference, grantJSON)
	if err != nil {
		return "", err
	}
	claims.AdditionalClaims = additional
	return aauth.MintAuthTokenCore(key, claims)
}

// VerifyMCPDirectAuthToken verifies Core trust, one complete R3 reference,
// and a strict r3_granted claim while refusing per-call and Budget claims.
// A Resource may enforce the trusted AS-signed grant directly without fetching
// the document. An issuer constructing a token without MintMCPDirectAuthToken
// must first call ParseReferencedDocument, ValidateDocumentAccount, and NewGrant.
func VerifyMCPDirectAuthToken(
	ctx context.Context,
	compact string,
	resolver signaturekey.KeyResolver,
	clock aauth.Clock,
) (aauth.AuthTokenClaims, Reference, GrantedOperations, error) {
	claims, err := aauth.VerifyAuthTokenCore(ctx, compact, resolver, clock)
	if err != nil {
		return aauth.AuthTokenClaims{}, Reference{}, GrantedOperations{}, err
	}
	if err := validateMCPDirectAuthClaims(claims.AdditionalClaims); err != nil {
		return aauth.AuthTokenClaims{}, Reference{}, GrantedOperations{}, err
	}
	reference, err := referenceFromClaims(claims.AdditionalClaims)
	if err != nil {
		return aauth.AuthTokenClaims{}, Reference{}, GrantedOperations{}, err
	}
	var granted GrantedOperations
	if err := json.Unmarshal(claims.AdditionalClaims[r3GrantedClaim], &granted); err != nil {
		return aauth.AuthTokenClaims{}, Reference{}, GrantedOperations{}, fmt.Errorf("r3: invalid r3_granted: %w", err)
	}
	removeClaims(&claims.AdditionalClaims, r3URIClaim, r3S256Claim, r3GrantedClaim)
	return claims, reference, granted, nil
}

// ValidateDocumentAccount requires exact presence and value parity between a
// Core token's account claim and its R3 document.
func ValidateDocumentAccount(document Document, tokenAccount *string) error {
	documentAccount, present := document.Account()
	if tokenAccount == nil {
		if present {
			return errors.New("document contains account but token does not")
		}
		return nil
	}
	if !present {
		return errors.New("token contains account but document does not")
	}
	if documentAccount != *tokenAccount {
		return errors.New("token and document account values differ")
	}
	return nil
}

func prepareMCPResourceClaims(additional map[string]json.RawMessage, reference Reference) (map[string]json.RawMessage, error) {
	prepared := cloneClaims(additional)
	if err := rejectClaimCollisions(aauth.ResourceTokenType, prepared, r3URIClaim, r3S256Claim); err != nil {
		return nil, err
	}
	if err := rejectUnsupportedMCPResourceClaims(aauth.ResourceTokenType, prepared); err != nil {
		return nil, err
	}
	if err := setStringClaim(prepared, r3URIClaim, reference.URI()); err != nil {
		return nil, err
	}
	if err := setStringClaim(prepared, r3S256Claim, reference.Digest()); err != nil {
		return nil, err
	}
	return prepared, nil
}

func prepareMCPDirectAuthClaims(
	additional map[string]json.RawMessage,
	reference Reference,
	grantJSON []byte,
) (map[string]json.RawMessage, error) {
	prepared := cloneClaims(additional)
	if err := rejectClaimCollisions(
		aauth.AuthTokenType, prepared, r3URIClaim, r3S256Claim, r3GrantedClaim,
	); err != nil {
		return nil, err
	}
	if err := rejectUnsupportedMCPDirectAuthClaims(aauth.AuthTokenType, prepared); err != nil {
		return nil, err
	}
	if err := setStringClaim(prepared, r3URIClaim, reference.URI()); err != nil {
		return nil, err
	}
	if err := setStringClaim(prepared, r3S256Claim, reference.Digest()); err != nil {
		return nil, err
	}
	prepared[r3GrantedClaim] = append(json.RawMessage(nil), grantJSON...)
	return prepared, nil
}

func validateMCPResourceClaims(additional map[string]json.RawMessage) error {
	if err := requireExactClaims(aauth.ResourceTokenType, additional, r3URIClaim, r3S256Claim); err != nil {
		return err
	}
	if err := rejectCaseVariants(aauth.ResourceTokenType, additional, r3URIClaim, r3S256Claim); err != nil {
		return err
	}
	return rejectUnsupportedMCPResourceClaims(aauth.ResourceTokenType, additional)
}

func validateMCPDirectAuthClaims(additional map[string]json.RawMessage) error {
	if err := requireExactClaims(
		aauth.AuthTokenType, additional, r3URIClaim, r3S256Claim, r3GrantedClaim,
	); err != nil {
		return err
	}
	if err := rejectCaseVariants(
		aauth.AuthTokenType, additional, r3URIClaim, r3S256Claim, r3GrantedClaim,
	); err != nil {
		return err
	}
	return rejectUnsupportedMCPDirectAuthClaims(aauth.AuthTokenType, additional)
}

func rejectUnsupportedMCPResourceClaims(tokenType string, additional map[string]json.RawMessage) error {
	if err := rejectFoldedClaims(
		tokenType, additional, "the claim belongs only in an Auth token", r3GrantedClaim,
	); err != nil {
		return err
	}
	if err := rejectFoldedClaims(
		tokenType, additional, "this MCP Resource-token API does not implement per-call authorization", r3PerCallClaim,
	); err != nil {
		return err
	}
	return rejectBudgetClaims(tokenType, additional)
}

func rejectUnsupportedMCPDirectAuthClaims(tokenType string, additional map[string]json.RawMessage) error {
	if err := rejectFoldedClaims(
		tokenType, additional, "this MCP direct profile does not implement per-call authorization", r3PerCallClaim,
	); err != nil {
		return err
	}
	return rejectBudgetClaims(tokenType, additional)
}

func referenceFromClaims(additional map[string]json.RawMessage) (Reference, error) {
	var uri, digest string
	if err := decodeJSONString(additional[r3URIClaim], &uri); err != nil {
		return Reference{}, fmt.Errorf("r3: invalid r3_uri: %w", err)
	}
	if err := decodeJSONString(additional[r3S256Claim], &digest); err != nil {
		return Reference{}, fmt.Errorf("r3: invalid r3_s256: %w", err)
	}
	return NewReference(uri, digest)
}

func requireExactClaims(tokenType string, additional map[string]json.RawMessage, names ...string) error {
	for _, name := range names {
		if _, present := additional[name]; !present {
			return fmt.Errorf("r3: %s requires %s", tokenType, name)
		}
	}
	return nil
}

func rejectCaseVariants(tokenType string, additional map[string]json.RawMessage, names ...string) error {
	for member := range additional {
		for _, name := range names {
			if member != name && strings.EqualFold(member, name) {
				return &aauth.UnsupportedTokenClaimError{
					TokenType: tokenType,
					Claim:     member,
					Reason:    "claim name is a noncanonical case variant of " + name,
				}
			}
		}
	}
	return nil
}

func rejectClaimCollisions(tokenType string, additional map[string]json.RawMessage, names ...string) error {
	for member := range additional {
		for _, name := range names {
			if strings.EqualFold(member, name) {
				return &aauth.UnsupportedTokenClaimError{
					TokenType: tokenType,
					Claim:     member,
					Reason:    "caller-supplied claim conflicts with typed " + name,
				}
			}
		}
	}
	return nil
}

func rejectFoldedClaims(tokenType string, additional map[string]json.RawMessage, reason string, names ...string) error {
	for _, name := range names {
		for member := range additional {
			if strings.EqualFold(member, name) {
				return &aauth.UnsupportedTokenClaimError{TokenType: tokenType, Claim: member, Reason: reason}
			}
		}
	}
	return nil
}

func rejectBudgetClaims(tokenType string, additional map[string]json.RawMessage) error {
	return rejectFoldedClaims(
		tokenType, additional, "this MCP R3 API does not validate the Budgets companion",
		"budget", "budget_consumed",
	)
}

func setStringClaim(additional map[string]json.RawMessage, name, value string) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	additional[name] = encoded
	return nil
}

func cloneClaims(claims map[string]json.RawMessage) map[string]json.RawMessage {
	cloned := make(map[string]json.RawMessage, len(claims)+3)
	for name, value := range claims {
		cloned[name] = append(json.RawMessage(nil), value...)
	}
	return cloned
}

func removeClaims(claims *map[string]json.RawMessage, names ...string) {
	if claims == nil || len(*claims) == 0 {
		return
	}
	for _, name := range names {
		delete(*claims, name)
	}
	if len(*claims) == 0 {
		*claims = nil
	}
}
