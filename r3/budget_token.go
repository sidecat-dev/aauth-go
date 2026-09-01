package r3

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const (
	budgetClaim         = "budget"
	budgetConsumedClaim = "budget_consumed"
)

// MintBudgetResourceToken mints one Resource token whose independent Core
// scope, R3 document, and Budget offer have all been validated. The ordinary
// R3-only and Budget-only token functions continue to reject this composition.
func MintBudgetResourceToken(
	registry Registry,
	key jose.SigningKey,
	claims aauth.ResourceTokenClaims,
	documentURI string,
	exactDocument []byte,
	offer budgets.Value,
	consumed []budgets.ConsumptionRecord,
) (string, Reference, error) {
	document, err := registry.ParseDocument(exactDocument)
	if err != nil {
		return "", Reference{}, fmt.Errorf("r3: Budget resource-token document: %w", err)
	}
	if err := ValidateDocumentAccount(document, claims.Account); err != nil {
		return "", Reference{}, fmt.Errorf("r3: Budget resource-token account: %w", err)
	}
	reference, err := NewReference(documentURI, Digest(exactDocument))
	if err != nil {
		return "", Reference{}, fmt.Errorf("r3: Budget resource-token reference: %w", err)
	}
	additional, err := prepareBudgetResourceClaims(claims, reference, offer, consumed)
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

// VerifyBudgetResourceToken verifies Core trust and consumes one complete R3
// class reference plus one complete Budget offer and consumption history.
func VerifyBudgetResourceToken(
	ctx context.Context,
	registry Registry,
	compact string,
	resolver signaturekey.KeyResolver,
	clock aauth.Clock,
) (aauth.ResourceTokenClaims, Reference, budgets.Value, []budgets.ConsumptionRecord, error) {
	claims, err := aauth.VerifyResourceTokenCore(ctx, compact, resolver, clock)
	if err != nil {
		return aauth.ResourceTokenClaims{}, Reference{}, budgets.Value{}, nil, err
	}
	if err := validateBudgetResourceClaims(claims.AdditionalClaims); err != nil {
		return aauth.ResourceTokenClaims{}, Reference{}, budgets.Value{}, nil, budgets.TokenClaimError(err)
	}
	reference, err := referenceFromClaims(claims.AdditionalClaims)
	if err != nil {
		return aauth.ResourceTokenClaims{}, Reference{}, budgets.Value{}, nil, err
	}
	offer, err := budgets.ParseValueJSON(claims.AdditionalClaims[budgetClaim])
	if err != nil {
		return aauth.ResourceTokenClaims{}, Reference{}, budgets.Value{}, nil, budgets.TokenClaimError(fmt.Errorf("r3: Budget resource-token offer: %w", err))
	}
	consumed, err := parseBudgetConsumption(claims.AdditionalClaims[budgetConsumedClaim])
	if err != nil {
		return aauth.ResourceTokenClaims{}, Reference{}, budgets.Value{}, nil, budgets.TokenClaimError(err)
	}
	removeClaims(&claims.AdditionalClaims, r3URIClaim, r3S256Claim, budgetClaim, budgetConsumedClaim)
	return claims, reference, offer, consumed, nil
}

// MintBudgetAuthToken mints one Auth token containing
// a proven R3 class grant and an independently narrowed fixed Budget grant.
func MintBudgetAuthToken(
	registry Registry,
	key jose.SigningKey,
	claims aauth.AuthTokenClaims,
	reference Reference,
	exactDocument []byte,
	operationGrant Grant,
	budgetGrant budgets.Value,
) (string, error) {
	document, err := registry.ParseReferencedDocument(reference, exactDocument)
	if err != nil {
		return "", fmt.Errorf("r3: Budget auth-token document: %w", err)
	}
	if err := ValidateDocumentAccount(document, claims.Account); err != nil {
		return "", fmt.Errorf("r3: Budget auth-token account: %w", err)
	}
	grantJSON, err := json.Marshal(operationGrant)
	if err != nil {
		return "", fmt.Errorf("r3: Budget auth-token operation grant: %w", err)
	}
	if _, err := registry.ParseGrant(grantJSON, document); err != nil {
		return "", fmt.Errorf("r3: Budget auth-token grant does not match referenced document: %w", err)
	}
	additional, err := prepareBudgetAuthClaims(claims, reference, grantJSON, budgetGrant)
	if err != nil {
		return "", err
	}
	claims.AdditionalClaims = additional
	return aauth.MintAuthTokenCore(key, claims)
}

// VerifyBudgetAuthToken verifies Core trust and consumes one R3 class grant
// and one fixed Budget grant from the same Auth token.
func VerifyBudgetAuthToken(
	ctx context.Context,
	registry Registry,
	compact string,
	resolver signaturekey.KeyResolver,
	clock aauth.Clock,
) (aauth.AuthTokenClaims, Reference, AuthTokenOperations, budgets.Value, error) {
	claims, err := aauth.VerifyAuthTokenCore(ctx, compact, resolver, clock)
	if err != nil {
		return aauth.AuthTokenClaims{}, Reference{}, AuthTokenOperations{}, budgets.Value{}, err
	}
	if err := validateBudgetAuthClaims(claims.AdditionalClaims); err != nil {
		return aauth.AuthTokenClaims{}, Reference{}, AuthTokenOperations{}, budgets.Value{}, err
	}
	reference, err := referenceFromClaims(claims.AdditionalClaims)
	if err != nil {
		return aauth.AuthTokenClaims{}, Reference{}, AuthTokenOperations{}, budgets.Value{}, err
	}
	granted, err := registry.ParseGrantedOperations(claims.AdditionalClaims[r3GrantedClaim])
	if err != nil {
		return aauth.AuthTokenClaims{}, Reference{}, AuthTokenOperations{}, budgets.Value{}, fmt.Errorf("r3: invalid r3_granted: %w", err)
	}
	grant, err := budgets.ParseValueJSON(claims.AdditionalClaims[budgetClaim])
	if err != nil {
		return aauth.AuthTokenClaims{}, Reference{}, AuthTokenOperations{}, budgets.Value{}, fmt.Errorf("r3: Budget auth-token grant: %w", err)
	}
	if err := budgets.ValidateFeedbackUnit(grant.Unit()); err != nil {
		return aauth.AuthTokenClaims{}, Reference{}, AuthTokenOperations{}, budgets.Value{}, err
	}
	vocabulary, ok := registry.Vocabulary(granted.Vocabulary())
	if !ok {
		return aauth.AuthTokenClaims{}, Reference{}, AuthTokenOperations{}, budgets.Value{}, errors.New("r3: Budget auth-token vocabulary is not registered")
	}
	emptyPerCall, err := NewGrantedOperations(vocabulary)
	if err != nil {
		return aauth.AuthTokenClaims{}, Reference{}, AuthTokenOperations{}, budgets.Value{}, err
	}
	removeClaims(&claims.AdditionalClaims, r3URIClaim, r3S256Claim, r3GrantedClaim, budgetClaim)
	return claims, reference, AuthTokenOperations{granted: granted, perCall: emptyPerCall}, grant, nil
}

func prepareBudgetResourceClaims(
	claims aauth.ResourceTokenClaims,
	reference Reference,
	offer budgets.Value,
	consumed []budgets.ConsumptionRecord,
) (map[string]json.RawMessage, error) {
	if len(consumed) > 20 {
		return nil, errors.New("r3: Budget Resource token must not issue more than 20 consumption records")
	}
	prepared := cloneClaims(claims.AdditionalClaims)
	if err := rejectClaimCollisions(aauth.ResourceTokenType, prepared, r3URIClaim, r3S256Claim, budgetClaim, budgetConsumedClaim); err != nil {
		return nil, err
	}
	if err := rejectFoldedClaims(aauth.ResourceTokenType, prepared, "the claim belongs only in an Auth token", r3GrantedClaim); err != nil {
		return nil, err
	}
	if err := rejectFoldedClaims(aauth.ResourceTokenType, prepared, "this combined Resource-token API does not implement per-call authorization", r3PerCallClaim); err != nil {
		return nil, err
	}
	if err := setStringClaim(prepared, r3URIClaim, reference.URI()); err != nil {
		return nil, err
	}
	if err := setStringClaim(prepared, r3S256Claim, reference.Digest()); err != nil {
		return nil, err
	}
	budgetJSON, err := json.Marshal(offer)
	if err != nil {
		return nil, fmt.Errorf("r3: Budget Resource-token offer: %w", err)
	}
	prepared[budgetClaim] = budgetJSON
	if len(consumed) != 0 {
		consumedJSON, err := json.Marshal(consumed)
		if err != nil {
			return nil, fmt.Errorf("r3: Budget Resource-token consumption records: %w", err)
		}
		prepared[budgetConsumedClaim] = consumedJSON
	}
	return prepared, nil
}

func prepareBudgetAuthClaims(
	claims aauth.AuthTokenClaims,
	reference Reference,
	operationGrantJSON []byte,
	budgetGrant budgets.Value,
) (map[string]json.RawMessage, error) {
	if err := budgets.ValidateFeedbackUnit(budgetGrant.Unit()); err != nil {
		return nil, err
	}
	prepared := cloneClaims(claims.AdditionalClaims)
	if err := rejectClaimCollisions(
		aauth.AuthTokenType, prepared,
		r3URIClaim, r3S256Claim, r3GrantedClaim, r3PerCallClaim, budgetClaim, budgetConsumedClaim,
	); err != nil {
		return nil, err
	}
	if err := setStringClaim(prepared, r3URIClaim, reference.URI()); err != nil {
		return nil, err
	}
	if err := setStringClaim(prepared, r3S256Claim, reference.Digest()); err != nil {
		return nil, err
	}
	prepared[r3GrantedClaim] = append(json.RawMessage(nil), operationGrantJSON...)
	budgetJSON, err := json.Marshal(budgetGrant)
	if err != nil {
		return nil, fmt.Errorf("r3: Budget Auth-token grant: %w", err)
	}
	prepared[budgetClaim] = budgetJSON
	return prepared, nil
}

func validateBudgetResourceClaims(additional map[string]json.RawMessage) error {
	if err := requireExactClaims(aauth.ResourceTokenType, additional, r3URIClaim, r3S256Claim, budgetClaim); err != nil {
		return err
	}
	if err := rejectCaseVariants(aauth.ResourceTokenType, additional, r3URIClaim, r3S256Claim, budgetClaim, budgetConsumedClaim); err != nil {
		return err
	}
	if err := rejectFoldedClaims(aauth.ResourceTokenType, additional, "the claim belongs only in an Auth token", r3GrantedClaim); err != nil {
		return err
	}
	return rejectFoldedClaims(aauth.ResourceTokenType, additional, "this combined Resource-token API does not implement per-call authorization", r3PerCallClaim)
}

func validateBudgetAuthClaims(additional map[string]json.RawMessage) error {
	if err := requireExactClaims(aauth.AuthTokenType, additional, r3URIClaim, r3S256Claim, r3GrantedClaim, budgetClaim); err != nil {
		return err
	}
	if err := rejectCaseVariants(aauth.AuthTokenType, additional, r3URIClaim, r3S256Claim, r3GrantedClaim, r3PerCallClaim, budgetClaim, budgetConsumedClaim); err != nil {
		return err
	}
	if err := rejectFoldedClaims(aauth.AuthTokenType, additional, "budget_consumed belongs only in a Resource token", budgetConsumedClaim); err != nil {
		return err
	}
	return rejectFoldedClaims(aauth.AuthTokenType, additional, "the class-R3 Budget profile does not permit r3_per_call", r3PerCallClaim)
}

func parseBudgetConsumption(raw json.RawMessage) ([]budgets.ConsumptionRecord, error) {
	if raw == nil {
		return nil, nil
	}
	if string(raw) == "null" {
		return nil, errors.New("r3: Budget Resource-token budget_consumed must be an array")
	}
	var consumed []budgets.ConsumptionRecord
	if err := json.Unmarshal(raw, &consumed); err != nil {
		return nil, fmt.Errorf("r3: Budget Resource-token budget_consumed: %w", err)
	}
	return consumed, nil
}
