package r3

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const (
	r3URIClaim     = "r3_uri"
	r3S256Claim    = "r3_s256"
	r3GrantedClaim = "r3_granted"
	r3PerCallClaim = "r3_per_call"
)

// MintResourceToken validates one exact registered-vocabulary document, binds its account to
// the Core claims, derives the document reference, and mints an R3 Resource
// token. Scope is optional at this wire boundary.
func MintResourceToken(
	registry Registry,
	key jose.SigningKey,
	claims aauth.ResourceTokenClaims,
	documentURI string,
	exactDocument []byte,
) (string, Reference, error) {
	document, err := registry.ParseDocument(exactDocument)
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
	additional, err := prepareResourceClaims(claims.AdditionalClaims, reference)
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

// MintProposalResourceToken validates one exact per-call proposal, binds
// its account to the Core claims, and mints the Resource token that carries
// the proposal reference to the Person and Access Servers.
func MintProposalResourceToken(
	registry Registry,
	key jose.SigningKey,
	claims aauth.ResourceTokenClaims,
	proposalURI string,
	exactProposal []byte,
) (string, Reference, error) {
	proposal, err := registry.ParseProposal(exactProposal)
	if err != nil {
		return "", Reference{}, fmt.Errorf("r3: proposal resource-token document: %w", err)
	}
	if err := ValidateProposalAccount(proposal, claims.Account); err != nil {
		return "", Reference{}, fmt.Errorf("r3: proposal resource-token account: %w", err)
	}
	reference, err := NewReference(proposalURI, Digest(exactProposal))
	if err != nil {
		return "", Reference{}, fmt.Errorf("r3: proposal resource-token reference: %w", err)
	}
	additional, err := prepareResourceClaims(claims.AdditionalClaims, reference)
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

// VerifyResourceToken verifies Core token trust and a complete R3
// reference. It validates only the signed reference syntax; it does not fetch
// or hash document bytes. Call ParseReferencedDocument after an entitled
// fetch, then ValidateDocumentAccount before policy.
func VerifyResourceToken(
	ctx context.Context,
	compact string,
	resolver signaturekey.KeyResolver,
	clock aauth.Clock,
) (aauth.ResourceTokenClaims, Reference, error) {
	claims, err := aauth.VerifyResourceTokenCore(ctx, compact, resolver, clock)
	if err != nil {
		return aauth.ResourceTokenClaims{}, Reference{}, err
	}
	if err := validateResourceClaims(claims.AdditionalClaims); err != nil {
		return aauth.ResourceTokenClaims{}, Reference{}, err
	}
	reference, err := referenceFromClaims(claims.AdditionalClaims)
	if err != nil {
		return aauth.ResourceTokenClaims{}, Reference{}, err
	}
	removeClaims(&claims.AdditionalClaims, r3URIClaim, r3S256Claim)
	return claims, reference, nil
}

// MintDirectAuthToken mints a direct-only R3 token after re-proving
// the supplied grant against the exact document bytes named by reference.
// It does not implement r3_per_call or Budgets composition.
func MintDirectAuthToken(
	registry Registry,
	key jose.SigningKey,
	claims aauth.AuthTokenClaims,
	reference Reference,
	exactDocument []byte,
	grant Grant,
) (string, error) {
	document, err := registry.ParseReferencedDocument(reference, exactDocument)
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
	if _, err := registry.ParseGrant(grantJSON, document); err != nil {
		return "", fmt.Errorf("r3: direct auth-token grant does not match referenced document: %w", err)
	}
	emptyPerCall, err := NewGrantedOperations(document.operationSet.value.vocabulary)
	if err != nil {
		return "", err
	}
	authorization, err := NewAuthorization(grant.GrantedOperations(), emptyPerCall, document)
	if err != nil {
		return "", err
	}
	return MintAuthToken(registry, key, claims, reference, exactDocument, authorization)
}

// MintAuthToken mints an R3 class Auth token after re-proving disjoint
// direct and per-call operation sets against the exact class document.
func MintAuthToken(
	registry Registry,
	key jose.SigningKey,
	claims aauth.AuthTokenClaims,
	reference Reference,
	exactDocument []byte,
	authorization Authorization,
) (string, error) {
	document, err := registry.ParseReferencedDocument(reference, exactDocument)
	if err != nil {
		return "", fmt.Errorf("r3: class auth-token document: %w", err)
	}
	if err := ValidateDocumentAccount(document, claims.Account); err != nil {
		return "", fmt.Errorf("r3: class auth-token account: %w", err)
	}
	if !authorization.proven {
		return "", errors.New("r3: class auth-token authorization is unproven")
	}
	proven, err := NewAuthorization(
		authorization.GrantedOperations(), authorization.PerCallOperations(), document,
	)
	if err != nil {
		return "", fmt.Errorf("r3: class auth-token authorization: %w", err)
	}
	grantedJSON, err := json.Marshal(proven.GrantedOperations())
	if err != nil {
		return "", fmt.Errorf("r3: class auth-token direct operations: %w", err)
	}
	var perCallJSON []byte
	if len(proven.PerCallOperations().Operations()) != 0 {
		perCallJSON, err = json.Marshal(proven.PerCallOperations())
		if err != nil {
			return "", fmt.Errorf("r3: class auth-token per-call operations: %w", err)
		}
	}
	additional, err := prepareAuthClaims(claims.AdditionalClaims, reference, grantedJSON, perCallJSON)
	if err != nil {
		return "", err
	}
	claims.AdditionalClaims = additional
	return aauth.MintAuthTokenCore(key, claims)
}

// MintPerCallAuthToken mints the one-operation Auth token for an approved
// exact proposal. It never carries r3_per_call forward.
func MintPerCallAuthToken(
	registry Registry,
	key jose.SigningKey,
	claims aauth.AuthTokenClaims,
	reference Reference,
	exactProposal []byte,
) (string, error) {
	proposal, err := registry.ParseReferencedProposal(reference, exactProposal)
	if err != nil {
		return "", fmt.Errorf("r3: per-call auth-token proposal: %w", err)
	}
	if err := ValidateProposalAccount(proposal, claims.Account); err != nil {
		return "", fmt.Errorf("r3: per-call auth-token account: %w", err)
	}
	granted, err := NewGrantedOperations(proposal.operation.value.vocabulary, proposal.Operation())
	if err != nil {
		return "", err
	}
	grantedJSON, err := json.Marshal(granted)
	if err != nil {
		return "", fmt.Errorf("r3: per-call auth-token operation: %w", err)
	}
	additional, err := prepareAuthClaims(claims.AdditionalClaims, reference, grantedJSON, nil)
	if err != nil {
		return "", err
	}
	claims.AdditionalClaims = additional
	return aauth.MintAuthTokenCore(key, claims)
}

// VerifyDirectAuthToken verifies Core trust, one complete R3 reference,
// and a strict r3_granted claim while refusing per-call and Budget claims.
// A Resource may enforce the trusted AS-signed grant directly without fetching
// the document. An issuer constructing a token without MintDirectAuthToken
// must first call ParseReferencedDocument, ValidateDocumentAccount, and NewGrant.
func VerifyDirectAuthToken(
	ctx context.Context,
	registry Registry,
	compact string,
	resolver signaturekey.KeyResolver,
	clock aauth.Clock,
) (aauth.AuthTokenClaims, Reference, GrantedOperations, error) {
	claims, reference, granted, perCall, perCallPresent, err := verifyAuthToken(ctx, registry, compact, resolver, clock)
	if err != nil {
		return aauth.AuthTokenClaims{}, Reference{}, GrantedOperations{}, err
	}
	if perCallPresent || len(perCall.Operations()) != 0 {
		return aauth.AuthTokenClaims{}, Reference{}, GrantedOperations{}, errors.New("r3: direct Auth token must not contain r3_per_call")
	}
	return claims, reference, granted, nil
}

// VerifyAuthTokenClaims verifies the signed R3 claim shape without
// classifying the referenced artifact. A Resource must establish class versus
// proposal custody before selecting direct or single-use enforcement.
func VerifyAuthTokenClaims(
	ctx context.Context,
	registry Registry,
	compact string,
	resolver signaturekey.KeyResolver,
	clock aauth.Clock,
) (aauth.AuthTokenClaims, Reference, AuthTokenOperations, error) {
	claims, reference, granted, perCall, perCallPresent, err := verifyAuthToken(ctx, registry, compact, resolver, clock)
	if err != nil {
		return aauth.AuthTokenClaims{}, Reference{}, AuthTokenOperations{}, err
	}
	return claims, reference, AuthTokenOperations{
		granted: granted, perCall: perCall, perCallPresent: perCallPresent,
	}, nil
}

// VerifyPerCallAuthToken verifies a granted-only token containing exactly
// one operation and no r3_per_call claim.
func VerifyPerCallAuthToken(
	ctx context.Context,
	registry Registry,
	compact string,
	resolver signaturekey.KeyResolver,
	clock aauth.Clock,
	expectedReference Reference,
	exactProposal []byte,
) (aauth.AuthTokenClaims, Reference, Operation, error) {
	proposal, err := registry.ParseReferencedProposal(expectedReference, exactProposal)
	if err != nil {
		return aauth.AuthTokenClaims{}, Reference{}, Operation{}, fmt.Errorf("r3: verify per-call proposal: %w", err)
	}
	claims, reference, granted, perCall, perCallPresent, err := verifyAuthToken(ctx, registry, compact, resolver, clock)
	if err != nil {
		return aauth.AuthTokenClaims{}, Reference{}, Operation{}, err
	}
	if perCallPresent || len(perCall.Operations()) != 0 {
		return aauth.AuthTokenClaims{}, Reference{}, Operation{}, errors.New("r3: per-call Auth token must not contain r3_per_call")
	}
	if reference != expectedReference {
		return aauth.AuthTokenClaims{}, Reference{}, Operation{}, errors.New("r3: per-call Auth token changed the proposal reference")
	}
	if err := ValidateProposalAccount(proposal, claims.Account); err != nil {
		return aauth.AuthTokenClaims{}, Reference{}, Operation{}, fmt.Errorf("r3: per-call Auth token account: %w", err)
	}
	operations := granted.Operations()
	if len(operations) != 1 {
		return aauth.AuthTokenClaims{}, Reference{}, Operation{}, errors.New("r3: per-call Auth token must grant exactly one operation")
	}
	equal, err := operations[0].Equal(proposal.Operation())
	if err != nil {
		return aauth.AuthTokenClaims{}, Reference{}, Operation{}, err
	}
	if !equal {
		return aauth.AuthTokenClaims{}, Reference{}, Operation{}, errors.New("r3: per-call Auth token granted an operation other than the proposal")
	}
	return claims, reference, operations[0], nil
}

func verifyAuthToken(
	ctx context.Context,
	registry Registry,
	compact string,
	resolver signaturekey.KeyResolver,
	clock aauth.Clock,
) (aauth.AuthTokenClaims, Reference, GrantedOperations, GrantedOperations, bool, error) {
	claims, err := aauth.VerifyAuthTokenCore(ctx, compact, resolver, clock)
	if err != nil {
		return aauth.AuthTokenClaims{}, Reference{}, GrantedOperations{}, GrantedOperations{}, false, err
	}
	if err := validateAuthClaims(claims.AdditionalClaims); err != nil {
		return aauth.AuthTokenClaims{}, Reference{}, GrantedOperations{}, GrantedOperations{}, false, err
	}
	reference, err := referenceFromClaims(claims.AdditionalClaims)
	if err != nil {
		return aauth.AuthTokenClaims{}, Reference{}, GrantedOperations{}, GrantedOperations{}, false, err
	}
	granted, err := registry.ParseGrantedOperations(claims.AdditionalClaims[r3GrantedClaim])
	if err != nil {
		return aauth.AuthTokenClaims{}, Reference{}, GrantedOperations{}, GrantedOperations{}, false, fmt.Errorf("r3: invalid r3_granted: %w", err)
	}
	perCall, err := NewGrantedOperations(granted.value.vocabulary)
	if err != nil {
		return aauth.AuthTokenClaims{}, Reference{}, GrantedOperations{}, GrantedOperations{}, false, err
	}
	perCallRaw, perCallPresent := claims.AdditionalClaims[r3PerCallClaim]
	if perCallPresent {
		perCall, err = registry.ParseGrantedOperations(perCallRaw)
		if err != nil {
			return aauth.AuthTokenClaims{}, Reference{}, GrantedOperations{}, GrantedOperations{}, false, fmt.Errorf("r3: invalid r3_per_call: %w", err)
		}
	}
	disjoint, err := granted.Disjoint(perCall)
	if err != nil {
		return aauth.AuthTokenClaims{}, Reference{}, GrantedOperations{}, GrantedOperations{}, false, err
	}
	if !disjoint {
		return aauth.AuthTokenClaims{}, Reference{}, GrantedOperations{}, GrantedOperations{}, false, errors.New("r3: r3_granted and r3_per_call overlap")
	}
	removeClaims(&claims.AdditionalClaims, r3URIClaim, r3S256Claim, r3GrantedClaim, r3PerCallClaim)
	return claims, reference, granted, perCall, perCallPresent, nil
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

func prepareResourceClaims(additional map[string]json.RawMessage, reference Reference) (map[string]json.RawMessage, error) {
	prepared := cloneClaims(additional)
	if err := rejectClaimCollisions(aauth.ResourceTokenType, prepared, r3URIClaim, r3S256Claim); err != nil {
		return nil, err
	}
	if err := rejectUnsupportedResourceClaims(aauth.ResourceTokenType, prepared); err != nil {
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

func prepareAuthClaims(
	additional map[string]json.RawMessage,
	reference Reference,
	grantJSON, perCallJSON []byte,
) (map[string]json.RawMessage, error) {
	prepared := cloneClaims(additional)
	if err := rejectClaimCollisions(
		aauth.AuthTokenType, prepared, r3URIClaim, r3S256Claim, r3GrantedClaim, r3PerCallClaim,
	); err != nil {
		return nil, err
	}
	if err := rejectBudgetClaims(aauth.AuthTokenType, prepared); err != nil {
		return nil, err
	}
	if err := setStringClaim(prepared, r3URIClaim, reference.URI()); err != nil {
		return nil, err
	}
	if err := setStringClaim(prepared, r3S256Claim, reference.Digest()); err != nil {
		return nil, err
	}
	prepared[r3GrantedClaim] = append(json.RawMessage(nil), grantJSON...)
	if len(perCallJSON) != 0 {
		prepared[r3PerCallClaim] = append(json.RawMessage(nil), perCallJSON...)
	}
	return prepared, nil
}

func validateResourceClaims(additional map[string]json.RawMessage) error {
	if err := requireExactClaims(aauth.ResourceTokenType, additional, r3URIClaim, r3S256Claim); err != nil {
		return err
	}
	if err := rejectCaseVariants(aauth.ResourceTokenType, additional, r3URIClaim, r3S256Claim); err != nil {
		return err
	}
	return rejectUnsupportedResourceClaims(aauth.ResourceTokenType, additional)
}

func validateAuthClaims(additional map[string]json.RawMessage) error {
	if err := requireExactClaims(
		aauth.AuthTokenType, additional, r3URIClaim, r3S256Claim, r3GrantedClaim,
	); err != nil {
		return err
	}
	if err := rejectCaseVariants(
		aauth.AuthTokenType, additional, r3URIClaim, r3S256Claim, r3GrantedClaim, r3PerCallClaim,
	); err != nil {
		return err
	}
	return rejectBudgetClaims(aauth.AuthTokenType, additional)
}

func rejectUnsupportedResourceClaims(tokenType string, additional map[string]json.RawMessage) error {
	if err := rejectFoldedClaims(
		tokenType, additional, "the claim belongs only in an Auth token", r3GrantedClaim,
	); err != nil {
		return err
	}
	if err := rejectFoldedClaims(
		tokenType, additional, "this R3 Resource-token API does not implement per-call authorization", r3PerCallClaim,
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
		tokenType, additional, "this R3 API does not validate the Budgets companion",
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
