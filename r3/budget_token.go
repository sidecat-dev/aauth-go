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
	consumed *budgets.ConsumptionRecord,
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

// MintBudgetProposalResourceToken mints the Resource token for a per-call
// proposal with a Budget offer: what the Resource draws down for the call it
// proposes, such as the release of a held result (R3 Approving Release Rather
// Than Execution; Budgets Deferred Delivery). It carries no consumption
// record: the token presented on the call is a class Auth token, which this
// profile gives no Budget.
func MintBudgetProposalResourceToken(
	registry Registry,
	key jose.SigningKey,
	claims aauth.ResourceTokenClaims,
	proposalURI string,
	exactProposal []byte,
	offer budgets.Value,
) (string, Reference, error) {
	proposal, err := registry.ParseProposal(exactProposal)
	if err != nil {
		return "", Reference{}, fmt.Errorf("r3: Budget proposal resource-token proposal: %w", err)
	}
	if err := ValidateProposalAccount(proposal, claims.Account); err != nil {
		return "", Reference{}, fmt.Errorf("r3: Budget proposal resource-token account: %w", err)
	}
	reference, err := NewReference(proposalURI, Digest(exactProposal))
	if err != nil {
		return "", Reference{}, fmt.Errorf("r3: Budget proposal resource-token reference: %w", err)
	}
	additional, err := prepareBudgetResourceClaims(claims, reference, offer, nil)
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
// reference, to a class document or a per-call proposal, plus one complete
// Budget offer and consumption history. The reference is not fetched here.
func VerifyBudgetResourceToken(
	ctx context.Context,
	registry Registry,
	compact string,
	resolver signaturekey.KeyResolver,
	clock aauth.Clock,
) (aauth.ResourceTokenClaims, Reference, budgets.Value, *budgets.ConsumptionRecord, error) {
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
	consumed, err := budgets.ParseConsumptionRecordJSON(claims.AdditionalClaims[budgetConsumedClaim], claims.PresentedJTI)
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

// MintBudgetPerCallAuthToken mints the one-operation Auth token for an
// approved exact proposal with a fixed Budget grant: MintPerCallAuthToken
// plus budget. The grant's unit must be representable in AAuth-Budget.
func MintBudgetPerCallAuthToken(
	registry Registry,
	key jose.SigningKey,
	claims aauth.AuthTokenClaims,
	reference Reference,
	exactProposal []byte,
	budgetGrant budgets.Value,
) (string, error) {
	grantedJSON, err := perCallGranted(registry, claims, reference, exactProposal)
	if err != nil {
		return "", err
	}
	additional, err := prepareBudgetAuthClaims(claims, reference, grantedJSON, budgetGrant)
	if err != nil {
		return "", err
	}
	claims.AdditionalClaims = additional
	return aauth.MintAuthTokenCore(key, claims)
}

// VerifyBudgetPerCallAuthToken verifies a per-call Auth token with a fixed
// Budget grant against the exact proposal it approves: the checks of
// VerifyPerCallAuthToken, and those of VerifyBudgetAuthToken for the grant.
func VerifyBudgetPerCallAuthToken(
	ctx context.Context,
	registry Registry,
	compact string,
	resolver signaturekey.KeyResolver,
	clock aauth.Clock,
	expectedReference Reference,
	exactProposal []byte,
) (aauth.AuthTokenClaims, Operation, budgets.Value, error) {
	proposal, err := registry.ParseReferencedProposal(expectedReference, exactProposal)
	if err != nil {
		return aauth.AuthTokenClaims{}, Operation{}, budgets.Value{}, fmt.Errorf("r3: verify Budget per-call proposal: %w", err)
	}
	claims, reference, operations, grant, err := VerifyBudgetAuthToken(ctx, registry, compact, resolver, clock)
	if err != nil {
		return aauth.AuthTokenClaims{}, Operation{}, budgets.Value{}, err
	}
	operation, err := perCallOperation(proposal, expectedReference, reference, operations.GrantedOperations(), claims.Account)
	if err != nil {
		return aauth.AuthTokenClaims{}, Operation{}, budgets.Value{}, err
	}
	return claims, operation, grant, nil
}

// VerifyBudgetAuthToken verifies Core trust and consumes one R3 grant and one
// fixed Budget grant from the same Auth token: a class grant, or the one
// operation of a per-call grant, which VerifyBudgetPerCallAuthToken checks
// against its proposal.
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
	consumed *budgets.ConsumptionRecord,
) (map[string]json.RawMessage, error) {
	if err := budgets.ValidateConsumptionRecord(consumed, claims.PresentedJTI); err != nil {
		return nil, err
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
	if consumed != nil {
		consumedJSON, err := json.Marshal(*consumed)
		if err != nil {
			return nil, fmt.Errorf("r3: Budget Resource-token consumption record: %w", err)
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
