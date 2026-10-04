package budgets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const (
	budgetClaim         = "budget"
	budgetConsumedClaim = "budget_consumed"
)

var r3Claims = [...]string{"r3_uri", "r3_s256", "r3_granted", "r3_per_call"}

type tokenClaimError struct{ cause error }

func (failure *tokenClaimError) Error() string { return failure.cause.Error() }
func (failure *tokenClaimError) Unwrap() error { return failure.cause }

// IsTokenClaimError reports whether Core token verification succeeded but the
// Budget companion claims were malformed. Token endpoints use this distinction
// to return the Budgets protocol's registered invalid_budget error.
func IsTokenClaimError(err error) bool {
	var failure *tokenClaimError
	return errors.As(err, &failure)
}

func invalidTokenClaims(err error) error {
	if err == nil {
		return nil
	}
	return &tokenClaimError{cause: err}
}

// TokenClaimError marks an error found after Core token verification while
// consuming Budget companion claims. Endpoints use it to return the
// registered invalid_budget response for composed token profiles too.
func TokenClaimError(err error) error { return invalidTokenClaims(err) }

// ConsumptionRecord reports metered consumption against one prior Auth token.
type ConsumptionRecord struct {
	jti      string
	consumed int64
}

// NewConsumptionRecord validates one prior Auth-token consumption record.
func NewConsumptionRecord(jti string, consumed int64) (ConsumptionRecord, error) {
	if jti == "" {
		return ConsumptionRecord{}, errors.New("budgets: consumption-record jti is required")
	}
	if !utf8.ValidString(jti) {
		return ConsumptionRecord{}, errors.New("budgets: consumption-record jti must be valid UTF-8")
	}
	if err := validateAmount("consumed", consumed); err != nil {
		return ConsumptionRecord{}, err
	}
	return ConsumptionRecord{jti: jti, consumed: consumed}, nil
}

// JTI returns the prior Auth token identifier.
func (record ConsumptionRecord) JTI() string { return record.jti }

// Consumed returns the amount metered against the prior Auth token.
func (record ConsumptionRecord) Consumed() int64 { return record.consumed }

func (record ConsumptionRecord) validate() error {
	validated, err := NewConsumptionRecord(record.jti, record.consumed)
	if err != nil {
		return err
	}
	if validated != record {
		return errors.New("budgets: consumption record is invalid")
	}
	return nil
}

type consumptionJSON struct {
	JTI      *string `json:"jti"`
	Consumed *int64  `json:"consumed"`
}

// MarshalJSON emits the exact Budget consumption-record object.
func (record ConsumptionRecord) MarshalJSON() ([]byte, error) {
	if err := record.validate(); err != nil {
		return nil, err
	}
	jti, consumed := record.jti, record.consumed
	return json.Marshal(consumptionJSON{JTI: &jti, Consumed: &consumed})
}

// UnmarshalJSON accepts only the exact Budget consumption-record object.
func (record *ConsumptionRecord) UnmarshalJSON(data []byte) error {
	if record == nil {
		return errors.New("budgets: nil ConsumptionRecord receiver")
	}
	var wire consumptionJSON
	if err := decodeStrictJSON(data, &wire); err != nil {
		return fmt.Errorf("budgets: parse consumption record: %w", err)
	}
	if wire.JTI == nil || wire.Consumed == nil {
		return errors.New("budgets: consumption record requires jti and consumed")
	}
	parsed, err := NewConsumptionRecord(*wire.JTI, *wire.Consumed)
	if err != nil {
		return err
	}
	*record = parsed
	return nil
}

// ValidateConsumptionRecord checks an optional Resource-token consumption
// record. A record names the Auth token presented on the request the Resource
// token answers, which the token carries as presented_jti.
func ValidateConsumptionRecord(consumed *ConsumptionRecord, presentedJTI string) error {
	if consumed == nil {
		return nil
	}
	if err := consumed.validate(); err != nil {
		return err
	}
	if consumed.jti != presentedJTI {
		return errors.New("budgets: Resource-token budget_consumed jti must equal presented_jti")
	}
	return nil
}

// ParseConsumptionRecordJSON parses the optional budget_consumed claim, a
// single consumption record for the presented Auth token. A nil claim is absent.
func ParseConsumptionRecordJSON(raw json.RawMessage, presentedJTI string) (*ConsumptionRecord, error) {
	if raw == nil {
		return nil, nil
	}
	var consumed ConsumptionRecord
	if err := json.Unmarshal(raw, &consumed); err != nil {
		return nil, fmt.Errorf("budgets: Resource-token budget_consumed: %w", err)
	}
	if err := ValidateConsumptionRecord(&consumed, presentedJTI); err != nil {
		return nil, err
	}
	return &consumed, nil
}

// MintResourceToken adds one validated Budget offer to Core Resource-token
// claims. The optional consumption record reports what the Auth token presented
// on the answered request has consumed, so its jti is the token's presented_jti.
func MintResourceToken(
	key jose.SigningKey,
	claims aauth.ResourceTokenClaims,
	offer Value,
	consumed *ConsumptionRecord,
) (string, error) {
	if err := validateBudgetScope(aauth.ResourceTokenType, claims.Scope); err != nil {
		return "", err
	}
	if err := offer.validate(); err != nil {
		return "", fmt.Errorf("budgets: Resource-token offer: %w", err)
	}
	if err := ValidateConsumptionRecord(consumed, claims.PresentedJTI); err != nil {
		return "", err
	}
	prepared, err := prepareClaims(aauth.ResourceTokenType, claims.AdditionalClaims)
	if err != nil {
		return "", err
	}
	budgetJSON, err := json.Marshal(offer)
	if err != nil {
		return "", err
	}
	prepared[budgetClaim] = budgetJSON
	if consumed != nil {
		consumedJSON, err := json.Marshal(*consumed)
		if err != nil {
			return "", fmt.Errorf("budgets: Resource-token consumption record: %w", err)
		}
		prepared[budgetConsumedClaim] = consumedJSON
	}
	claims.AdditionalClaims = prepared
	return aauth.MintResourceTokenCore(key, claims)
}

// VerifyResourceToken verifies Core trust and consumes the complete Budget
// companion claim set.
func VerifyResourceToken(
	ctx context.Context,
	compact string,
	resolver signaturekey.KeyResolver,
	clock aauth.Clock,
) (aauth.ResourceTokenClaims, Value, *ConsumptionRecord, error) {
	claims, err := aauth.VerifyResourceTokenCore(ctx, compact, resolver, clock)
	if err != nil {
		return aauth.ResourceTokenClaims{}, Value{}, nil, err
	}
	if err := validateBudgetScope(aauth.ResourceTokenType, claims.Scope); err != nil {
		return aauth.ResourceTokenClaims{}, Value{}, nil, invalidTokenClaims(err)
	}
	if err := validateCompanionClaims(aauth.ResourceTokenType, claims.AdditionalClaims, true); err != nil {
		return aauth.ResourceTokenClaims{}, Value{}, nil, invalidTokenClaims(err)
	}
	offer, err := ParseValueJSON(claims.AdditionalClaims[budgetClaim])
	if err != nil {
		return aauth.ResourceTokenClaims{}, Value{}, nil, invalidTokenClaims(fmt.Errorf("budgets: Resource-token budget: %w", err))
	}
	consumed, err := ParseConsumptionRecordJSON(claims.AdditionalClaims[budgetConsumedClaim], claims.PresentedJTI)
	if err != nil {
		return aauth.ResourceTokenClaims{}, Value{}, nil, invalidTokenClaims(err)
	}
	removeClaims(&claims.AdditionalClaims, budgetClaim, budgetConsumedClaim)
	return claims, offer, consumed, nil
}

// MintAuthToken adds one validated Budget grant to Core Auth-token claims.
func MintAuthToken(key jose.SigningKey, claims aauth.AuthTokenClaims, grant Value) (string, error) {
	if err := validateBudgetScope(aauth.AuthTokenType, claims.Scope); err != nil {
		return "", err
	}
	if err := ValidateFeedbackUnit(grant.Unit()); err != nil {
		return "", err
	}
	if err := grant.validate(); err != nil {
		return "", fmt.Errorf("budgets: Auth-token grant: %w", err)
	}
	prepared, err := prepareClaims(aauth.AuthTokenType, claims.AdditionalClaims)
	if err != nil {
		return "", err
	}
	budgetJSON, err := json.Marshal(grant)
	if err != nil {
		return "", err
	}
	prepared[budgetClaim] = budgetJSON
	claims.AdditionalClaims = prepared
	return aauth.MintAuthTokenCore(key, claims)
}

// VerifyAuthToken verifies Core trust and consumes the complete Budget
// companion claim set.
func VerifyAuthToken(
	ctx context.Context,
	compact string,
	resolver signaturekey.KeyResolver,
	clock aauth.Clock,
) (aauth.AuthTokenClaims, Value, error) {
	claims, err := aauth.VerifyAuthTokenCore(ctx, compact, resolver, clock)
	if err != nil {
		return aauth.AuthTokenClaims{}, Value{}, err
	}
	if err := validateBudgetScope(aauth.AuthTokenType, claims.Scope); err != nil {
		return aauth.AuthTokenClaims{}, Value{}, invalidTokenClaims(err)
	}
	if err := validateCompanionClaims(aauth.AuthTokenType, claims.AdditionalClaims, false); err != nil {
		return aauth.AuthTokenClaims{}, Value{}, invalidTokenClaims(err)
	}
	grant, err := ParseValueJSON(claims.AdditionalClaims[budgetClaim])
	if err != nil {
		return aauth.AuthTokenClaims{}, Value{}, invalidTokenClaims(fmt.Errorf("budgets: Auth-token budget: %w", err))
	}
	if err := ValidateFeedbackUnit(grant.Unit()); err != nil {
		return aauth.AuthTokenClaims{}, Value{}, invalidTokenClaims(err)
	}
	removeClaims(&claims.AdditionalClaims, budgetClaim)
	return claims, grant, nil
}

func validateBudgetScope(tokenType, scope string) error {
	if scope == "" {
		return fmt.Errorf("budgets: %s scope is required because Budget does not replace Core scope", tokenType)
	}
	if _, err := aauth.ParseScope(scope); err != nil {
		return fmt.Errorf("budgets: %s scope: %w", tokenType, err)
	}
	return nil
}

// TokenCarriesClaims reports whether an unverified compact token names a
// Budget claim, including partial and case-variant forms that must route to
// strict Budget verification.
func TokenCarriesClaims(compact string) (bool, error) {
	parsed, err := jose.ParseCompact(compact)
	if err != nil {
		return false, err
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(parsed.Payload(), &members); err != nil {
		return false, err
	}
	for member := range members {
		if strings.EqualFold(member, budgetClaim) || strings.EqualFold(member, budgetConsumedClaim) {
			return true, nil
		}
	}
	return false, nil
}

func prepareClaims(tokenType string, additional map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	prepared := cloneClaims(additional)
	for member := range prepared {
		if strings.EqualFold(member, budgetClaim) || strings.EqualFold(member, budgetConsumedClaim) {
			return nil, unsupportedClaim(tokenType, member, "caller-supplied claim conflicts with the typed Budgets companion")
		}
		if isR3Claim(member) {
			return nil, unsupportedClaim(tokenType, member, "this Budgets API does not validate the R3 companion")
		}
	}
	return prepared, nil
}

func validateCompanionClaims(tokenType string, additional map[string]json.RawMessage, allowConsumed bool) error {
	budgetPresent := false
	for member := range additional {
		switch {
		case member == budgetClaim:
			budgetPresent = true
		case strings.EqualFold(member, budgetClaim):
			return unsupportedClaim(tokenType, member, "claim name is a noncanonical case variant of budget")
		case member == budgetConsumedClaim && allowConsumed:
			// Parsed after the complete companion shape is established.
		case strings.EqualFold(member, budgetConsumedClaim):
			reason := "budget_consumed belongs only in a Resource token"
			if allowConsumed && member != budgetConsumedClaim {
				reason = "claim name is a noncanonical case variant of budget_consumed"
			}
			return unsupportedClaim(tokenType, member, reason)
		case isR3Claim(member):
			return unsupportedClaim(tokenType, member, "this Budgets API does not validate the R3 companion")
		}
	}
	if !budgetPresent {
		return errors.New("budgets: typed token requires a budget claim")
	}
	return nil
}

func isR3Claim(member string) bool {
	for _, name := range r3Claims {
		if strings.EqualFold(member, name) {
			return true
		}
	}
	return false
}

func unsupportedClaim(tokenType, claim, reason string) error {
	return &aauth.UnsupportedTokenClaimError{TokenType: tokenType, Claim: claim, Reason: reason}
}

func cloneClaims(claims map[string]json.RawMessage) map[string]json.RawMessage {
	cloned := make(map[string]json.RawMessage, len(claims)+2)
	for name, value := range claims {
		cloned[name] = append(json.RawMessage(nil), value...)
	}
	return cloned
}

func removeClaims(claims *map[string]json.RawMessage, names ...string) {
	if claims == nil {
		return
	}
	for _, name := range names {
		delete(*claims, name)
	}
	if len(*claims) == 0 {
		*claims = nil
	}
}
