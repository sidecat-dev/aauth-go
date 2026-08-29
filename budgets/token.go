package budgets

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
)

// TokenResult is invalid-zero evidence that one exact verified Core token
// carries a valid Budget allocation and consumption projection.
type TokenResult struct {
	coreID      aauth.EvidenceID
	tokenType   string
	budget      Budget
	consumption []Consumption
	seal        [sha256.Size]byte
}

// BindResourceToken adds one Budget offer and optional recent consumption to
// a composable Core resource-token draft.
func BindResourceToken(
	draft aauth.TokenDraft[aauth.ResourceTokenClaims],
	budget Budget,
	consumption []Consumption,
) (aauth.TokenDraft[aauth.ResourceTokenClaims], error) {
	if err := budget.Validate(); err != nil {
		return aauth.TokenDraft[aauth.ResourceTokenClaims]{}, err
	}
	if err := validateConsumption(consumption); err != nil {
		return aauth.TokenDraft[aauth.ResourceTokenClaims]{}, err
	}
	budgetJSON, err := json.Marshal(budget)
	if err != nil {
		return aauth.TokenDraft[aauth.ResourceTokenClaims]{}, err
	}
	members := map[string]json.RawMessage{"budget": budgetJSON}
	if consumption != nil {
		consumptionJSON, err := json.Marshal(consumption)
		if err != nil {
			return aauth.TokenDraft[aauth.ResourceTokenClaims]{}, err
		}
		members["budget_consumed"] = consumptionJSON
	}
	return draft.WithAuthorizationMembers(members)
}

// BindAuthToken adds one granted Budget to a composable Core auth-token draft.
func BindAuthToken(
	draft aauth.TokenDraft[aauth.AuthTokenClaims],
	budget Budget,
) (aauth.TokenDraft[aauth.AuthTokenClaims], error) {
	if err := budget.Validate(); err != nil {
		return aauth.TokenDraft[aauth.AuthTokenClaims]{}, err
	}
	exact, err := json.Marshal(budget)
	if err != nil {
		return aauth.TokenDraft[aauth.AuthTokenClaims]{}, err
	}
	return draft.WithAuthorizationMembers(map[string]json.RawMessage{"budget": exact})
}

// ValidateResourceToken validates Budget members retained by exact Core
// resource-token evidence.
func ValidateResourceToken(core aauth.VerifiedToken[aauth.ResourceTokenClaims]) (TokenResult, error) {
	return validateToken(core, aauth.ResourceTokenType, true)
}

// ValidateAuthToken validates the Budget member retained by exact Core
// auth-token evidence.
func ValidateAuthToken(core aauth.VerifiedToken[aauth.AuthTokenClaims]) (TokenResult, error) {
	return validateToken(core, aauth.AuthTokenType, false)
}

func validateToken[T aauth.ResourceTokenClaims | aauth.AuthTokenClaims](
	core aauth.VerifiedToken[T], tokenType string, allowConsumption bool,
) (TokenResult, error) {
	members, err := core.AuthorizationMembers()
	if err != nil {
		return TokenResult{}, err
	}
	raw, present := members["budget"]
	if !present {
		return TokenResult{}, errors.New("aauth budgets: verified token does not carry budget")
	}
	budget, err := ParseBudget(raw)
	if err != nil {
		return TokenResult{}, err
	}
	var consumption []Consumption
	if rawConsumption, present := members["budget_consumed"]; present {
		if !allowConsumption {
			return TokenResult{}, errors.New("aauth budgets: auth token cannot carry consumption records")
		}
		consumption, err = parseConsumption(rawConsumption)
		if err != nil {
			return TokenResult{}, err
		}
	}
	coreID, err := core.EvidenceID()
	if err != nil {
		return TokenResult{}, err
	}
	result := TokenResult{
		coreID: coreID, tokenType: tokenType, budget: budget,
		consumption: cloneConsumption(consumption),
	}
	result.seal = result.sealValue()
	return result, nil
}

func parseConsumption(exact []byte) ([]Consumption, error) {
	if err := jsonstrict.RejectAmbiguousNames(exact); err != nil {
		return nil, fmt.Errorf("aauth budgets: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(exact))
	decoder.DisallowUnknownFields()
	var records []Consumption
	if err := decoder.Decode(&records); err != nil {
		return nil, fmt.Errorf("aauth budgets: parse consumption: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("aauth budgets: consumption must contain one JSON value")
	}
	if records == nil {
		return nil, errors.New("aauth budgets: consumption must be an array")
	}
	if err := validateConsumption(records); err != nil {
		return nil, err
	}
	return records, nil
}

// Valid reports whether the result remains bound to the same Core evidence and
// Budget projection.
func (result TokenResult) Valid() bool {
	return result.seal != [sha256.Size]byte{} && result.seal == result.sealValue()
}

// CoreEvidenceID returns the exact Core token evidence identity.
func (result TokenResult) CoreEvidenceID() aauth.EvidenceID {
	if !result.Valid() {
		return aauth.EvidenceID{}
	}
	return result.coreID
}

// Budget returns the validated allocation.
func (result TokenResult) Budget() (Budget, error) {
	if !result.Valid() {
		return Budget{}, errors.New("aauth budgets: token result is invalid")
	}
	return result.budget, nil
}

// Consumption returns an independent copy of recent resource-token records.
func (result TokenResult) Consumption() ([]Consumption, error) {
	if !result.Valid() {
		return nil, errors.New("aauth budgets: token result is invalid")
	}
	return cloneConsumption(result.consumption), nil
}

// ValidateGrant proves that an auth-token allocation only narrows the exact
// denomination offered in the preceding resource token.
func ValidateGrant(resource TokenResult, auth TokenResult) error {
	if !resource.Valid() || !auth.Valid() || resource.tokenType != aauth.ResourceTokenType || auth.tokenType != aauth.AuthTokenType {
		return errors.New("aauth budgets: token result is invalid")
	}
	if resource.budget.Unit != auth.budget.Unit || resource.budget.Decimals != auth.budget.Decimals {
		return errors.New("aauth budgets: auth token changed the resource denomination")
	}
	if auth.budget.Amount > resource.budget.Amount {
		return errors.New("aauth budgets: auth token exceeds the resource allocation")
	}
	return nil
}

func (result TokenResult) sealValue() [sha256.Size]byte {
	if result.coreID.String() == "" || result.tokenType == "" || result.budget.Validate() != nil || validateConsumption(result.consumption) != nil {
		return [sha256.Size]byte{}
	}
	exact, err := json.Marshal(struct {
		Domain      string        `json:"domain"`
		CoreID      string        `json:"core_id"`
		TokenType   string        `json:"token_type"`
		Budget      Budget        `json:"budget"`
		Consumption []Consumption `json:"consumption,omitempty"`
	}{
		Domain: "gitlab.com/sidecat-dev/aauth-go/budgets-token-result/v1",
		CoreID: result.coreID.String(), TokenType: result.tokenType,
		Budget: result.budget, Consumption: result.consumption,
	})
	if err != nil {
		return [sha256.Size]byte{}
	}
	return sha256.Sum256(exact)
}
