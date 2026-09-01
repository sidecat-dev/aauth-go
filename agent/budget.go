package agent

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/internal/r3dispatch"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// BudgetCall supplies one fixed-price protected request and its Budget Auth
// token. When no trustworthy response arrives, BeginBudgetCall conservatively
// assumes the entire signed grant because Core exposes no verified current
// balance and Budgets defines no interoperable maximum-cost input.
type BudgetCall struct {
	Request   *http.Request
	AuthToken string
}

type budgetCallResultKind uint8
type budgetAuthorizationKind uint8

const (
	budgetCallResultResponse budgetCallResultKind = iota + 1
	budgetCallResultAuthorizationRequired
)

const budgetAuthorizationVerified budgetAuthorizationKind = 1

// BudgetAuthorization is one verified auth-token requirement returned by a
// Budget call. Only BeginBudgetCall can construct a usable value.
type BudgetAuthorization struct {
	kind          budgetAuthorizationKind
	resourceToken string
	reason        budgets.Reason
}

// ResourceToken returns the verified Resource token to exchange explicitly.
func (authorization BudgetAuthorization) ResourceToken() string {
	if authorization.kind != budgetAuthorizationVerified {
		return ""
	}
	return authorization.resourceToken
}

// Reason returns the optional registered Budget reason. A missing reason is
// an ordinary Core auth-token step-up.
func (authorization BudgetAuthorization) Reason() (budgets.Reason, bool) {
	if authorization.kind != budgetAuthorizationVerified || authorization.reason == "" {
		return "", false
	}
	return authorization.reason, true
}

// BudgetCallResult is exactly one caller-owned application response or one
// verified authorization step-up. Current responses carry validated Budget
// feedback; feedback from any Age-bearing response is ignored as a
// conservative observable approximation of the draft's current-age rule.
type BudgetCallResult struct {
	kind          budgetCallResultKind
	response      *http.Response
	authorization BudgetAuthorization
	feedback      budgets.Feedback
	hasFeedback   bool
	grant         budgets.Value
}

// Response returns the application response, when present. The caller owns
// and closes its body.
func (result BudgetCallResult) Response() (*http.Response, bool) {
	if result.kind != budgetCallResultResponse || result.response == nil {
		return nil, false
	}
	return result.response, true
}

// AuthorizationRequired returns the verified step-up, when present.
func (result BudgetCallResult) AuthorizationRequired() (BudgetAuthorization, bool) {
	if result.kind != budgetCallResultAuthorizationRequired ||
		result.authorization.kind != budgetAuthorizationVerified {
		return BudgetAuthorization{}, false
	}
	return result.authorization, true
}

// Feedback returns the validated AAuth-Budget field carried by the response.
func (result BudgetCallResult) Feedback() (budgets.Feedback, bool) {
	if result.kind == 0 || !result.hasFeedback {
		return budgets.Feedback{}, false
	}
	return result.feedback, true
}

// Grant returns the signed Budget grant used for the call.
func (result BudgetCallResult) Grant() (budgets.Value, bool) {
	if result.kind == 0 {
		return budgets.Value{}, false
	}
	return result.grant, true
}

// Cost returns the exact request cost reported by the Resource.
func (result BudgetCallResult) Cost() (int64, bool) {
	if result.kind == 0 || !result.hasFeedback {
		return 0, false
	}
	return result.feedback.Cost()
}

// BudgetCallUncertainError reports an attempted Budget request whose exact
// metering outcome is unavailable. Callers must carry AssumedCost and must
// not automatically retry the chargeable request.
type BudgetCallUncertainError struct {
	cause       error
	grant       budgets.Value
	assumedCost budgets.Value
}

func (failure *BudgetCallUncertainError) Error() string {
	if failure == nil || failure.cause == nil {
		return "aauth agent: Budget call outcome is uncertain"
	}
	return "aauth agent: Budget call outcome is uncertain: " + failure.cause.Error()
}

func (failure *BudgetCallUncertainError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.cause
}

// AssumedCost returns the conservative charge to carry until a later
// response's remaining balance supersedes it.
func (failure *BudgetCallUncertainError) AssumedCost() (budgets.Value, bool) {
	if failure == nil {
		return budgets.Value{}, false
	}
	return failure.assumedCost, true
}

// Grant returns the signed Budget grant used for the attempted request.
func (failure *BudgetCallUncertainError) Grant() (budgets.Value, bool) {
	if failure == nil {
		return budgets.Value{}, false
	}
	return failure.grant, true
}

// BeginBudgetCall verifies one Budget Auth token, attempts exactly one signed
// application request, and returns one closed result. It never exchanges a
// token, retries the request, polls, sleeps, or retains local Budget state.
func (client *Client) BeginBudgetCall(ctx context.Context, call BudgetCall) (BudgetCallResult, error) {
	const operation = "begin Budget call"
	if client == nil {
		return BudgetCallResult{}, fail(operation, errors.New("client is required"))
	}
	if ctx == nil {
		return BudgetCallResult{}, fail(operation, errors.New("context is required"))
	}
	if err := ctx.Err(); err != nil {
		return BudgetCallResult{}, fail(operation, err)
	}
	if call.Request == nil || call.Request.URL == nil {
		return BudgetCallResult{}, fail(operation, errors.New("request is required"))
	}
	if call.AuthToken == "" {
		return BudgetCallResult{}, fail(operation, errors.New("auth token is required"))
	}
	resource, err := requestOrigin(call.Request.URL)
	if err != nil {
		return BudgetCallResult{}, fail(operation, err)
	}
	carriesR3, err := r3dispatch.TokenCarriesClaims(call.AuthToken)
	if err != nil {
		return BudgetCallResult{}, fail(operation, err)
	}
	carriesBudget, err := budgets.TokenCarriesClaims(call.AuthToken)
	if err != nil {
		return BudgetCallResult{}, fail(operation, err)
	}
	if carriesR3 && carriesBudget {
		if client.r3 == nil {
			return BudgetCallResult{}, fail(operation, errors.New("R3 is not configured"))
		}
	} else if !carriesBudget {
		return BudgetCallResult{}, fail(operation, errors.New("Budget Auth token is required"))
	}
	var claims aauth.AuthTokenClaims
	var grant budgets.Value
	var r3Reference *r3.Reference
	if carriesR3 {
		var reference r3.Reference
		claims, reference, _, grant, err = r3.VerifyDirectBudgetAuthToken(
			ctx, client.r3.Registry, call.AuthToken, client.keyResolver, client.clock,
		)
		if err == nil {
			_, err = client.validateR3AuthTokenForCallClaims(ctx, claims, resource)
		}
		if err == nil {
			r3Reference = &reference
		}
	} else {
		claims, grant, err = budgets.VerifyAuthToken(ctx, call.AuthToken, client.keyResolver, client.clock)
		if err == nil {
			err = client.validateAuthTokenForDirectCall(ctx, claims, resource, "")
		}
	}
	if err != nil {
		return BudgetCallResult{}, fail(operation, err)
	}
	if claims.Account != nil {
		return BudgetCallResult{}, fail(operation, errors.New("account-bound Budget use is not implemented"))
	}
	metadata, err := client.resourceMetadata(ctx, resource)
	if err != nil {
		return BudgetCallResult{}, fail(operation, err)
	}
	request, err := cloneInitialRequest(ctx, call.Request)
	if err != nil {
		return BudgetCallResult{}, fail(operation, err)
	}
	handedOff := false
	if request.Body != nil && request.Body != http.NoBody {
		defer func() {
			if !handedOff {
				_ = request.Body.Close()
			}
		}()
	}
	signOptions := signaturekey.SignOptions{
		AdditionalComponents: append([]string(nil), metadata.AdditionalSignatureComponents...),
	}
	if containsFold(metadata.AdditionalSignatureComponents, "content-digest") {
		signOptions.MaxBodyBytes = client.maxSignedBodyBytes
	}
	if err := signaturekey.SignJWTRequestWithOptions(
		request, client.signingKey, call.AuthToken, client.clock, signOptions,
	); err != nil {
		return BudgetCallResult{}, fail(operation, err)
	}
	handedOff = true
	response, err := client.httpClient.Do(request)
	if err != nil {
		closeResponse(response)
		return BudgetCallResult{}, fail(operation, newBudgetUncertain(err, grant))
	}
	if err := validateCallResponseOrigin(response, resource); err != nil {
		closeResponse(response)
		return BudgetCallResult{}, fail(operation, newBudgetUncertain(err, grant))
	}
	if response.StatusCode == http.StatusUnauthorized && response.Header.Get("Signature-Error") != "" {
		closeResponse(response)
		return BudgetCallResult{}, fail(operation, responseFailure(response))
	}
	cached, err := responseCarriesAge(response.Header.Values("Age"))
	if err != nil {
		closeResponse(response)
		return BudgetCallResult{}, fail(operation, newBudgetUncertain(err, grant))
	}
	if cached {
		if response.StatusCode == http.StatusUnauthorized && len(response.Header.Values("AAuth-Requirement")) > 0 {
			closeResponse(response)
			return BudgetCallResult{}, fail(operation, newBudgetUncertain(
				errors.New("cached Budget authorization requirement is not current"), grant,
			))
		}
		return BudgetCallResult{
			kind: budgetCallResultResponse, response: response, grant: grant,
		}, nil
	}
	feedback, err := parseBudgetCallFeedback(response, grant)
	if err != nil {
		closeResponse(response)
		return BudgetCallResult{}, fail(operation, newBudgetUncertain(err, grant))
	}
	if response.StatusCode == http.StatusUnauthorized && len(response.Header.Values("AAuth-Requirement")) > 0 {
		authorization, err := client.verifyBudgetCallAuthorization(
			ctx, response.Header.Values("AAuth-Requirement"), claims, resource, metadata, r3Reference,
		)
		closeResponse(response)
		if err != nil {
			return BudgetCallResult{}, fail(operation, newBudgetUncertain(err, grant))
		}
		if err := validateBudgetStepUpFeedback(authorization, feedback); err != nil {
			return BudgetCallResult{}, fail(operation, newBudgetUncertain(err, grant))
		}
		return BudgetCallResult{
			kind: budgetCallResultAuthorizationRequired, authorization: authorization,
			feedback: feedback, hasFeedback: true, grant: grant,
		}, nil
	}
	if _, present := feedback.Cost(); !present {
		closeResponse(response)
		return BudgetCallResult{}, fail(operation, newBudgetUncertain(
			errors.New("fixed-price Budget response omitted cost"), grant,
		))
	}
	if _, present := feedback.Required(); present {
		closeResponse(response)
		return BudgetCallResult{}, fail(operation, newBudgetUncertain(
			errors.New("ordinary Budget response unexpectedly reported required"), grant,
		))
	}
	return BudgetCallResult{
		kind: budgetCallResultResponse, response: response, feedback: feedback,
		hasFeedback: true, grant: grant,
	}, nil
}

func responseCarriesAge(values []string) (bool, error) {
	if len(values) == 0 {
		return false, nil
	}
	if len(values) != 1 || values[0] == "" {
		return false, errors.New("Budget response Age must be one nonnegative integer")
	}
	if _, err := strconv.ParseUint(values[0], 10, 64); err != nil {
		return false, errors.New("Budget response Age must be one nonnegative integer")
	}
	return true, nil
}

func validateBudgetStepUpFeedback(
	authorization BudgetAuthorization,
	feedback budgets.Feedback,
) error {
	reason, present := authorization.Reason()
	if _, reported := feedback.Cost(); reported {
		return errors.New("refused Budget request unexpectedly reported a current-request cost")
	}
	if !present {
		if _, reported := feedback.Required(); reported {
			return errors.New("reasonless auth-token step-up unexpectedly reported a Budget requirement")
		}
		return nil
	}
	switch reason {
	case budgets.ReasonBudgetExhausted:
		if feedback.Remaining() != 0 {
			return errors.New("budget-exhausted step-up reported a nonzero remainder")
		}
		if _, required := feedback.Required(); required {
			return errors.New("budget-exhausted step-up unexpectedly reported required")
		}
	case budgets.ReasonInsufficientBudget:
		if required, reported := feedback.Required(); reported && required <= feedback.Remaining() {
			return errors.New("insufficient-budget step-up required amount fits the reported remainder")
		}
	}
	return nil
}

func newBudgetUncertain(cause error, grant budgets.Value) *BudgetCallUncertainError {
	return &BudgetCallUncertainError{cause: cause, grant: grant, assumedCost: grant}
}

func parseBudgetCallFeedback(response *http.Response, grant budgets.Value) (budgets.Feedback, error) {
	values := response.Header.Values("AAuth-Budget")
	if len(values) == 0 {
		return budgets.Feedback{}, errors.New("Budget response omitted AAuth-Budget")
	}
	feedback, err := budgets.ParseFeedback(values)
	if err != nil {
		return budgets.Feedback{}, err
	}
	if err := budgets.ValidateFeedback(grant, feedback); err != nil {
		return budgets.Feedback{}, err
	}
	return feedback, nil
}

func (client *Client) verifyBudgetCallAuthorization(
	ctx context.Context,
	values []string,
	current aauth.AuthTokenClaims,
	resource string,
	metadata resourceMetadata,
	expectedR3Reference *r3.Reference,
) (BudgetAuthorization, error) {
	requirement, reason, reasonPresent, err := budgets.ParseOptionalAuthTokenRequirement(values)
	if err != nil {
		return BudgetAuthorization{}, err
	}
	carriesBudget, err := budgets.TokenCarriesClaims(requirement.ResourceToken)
	if err != nil {
		return BudgetAuthorization{}, err
	}
	var challenge aauth.ResourceTokenClaims
	carriesR3, err := r3dispatch.TokenCarriesClaims(requirement.ResourceToken)
	if err != nil {
		return BudgetAuthorization{}, err
	}
	if carriesBudget && carriesR3 {
		if client.r3 == nil || expectedR3Reference == nil {
			return BudgetAuthorization{}, errors.New("unexpected combined R3 and Budget step-up")
		}
		var reference r3.Reference
		var offer budgets.Value
		challenge, reference, offer, _, err = r3.VerifyBudgetResourceToken(
			ctx, client.r3.Registry, requirement.ResourceToken, client.keyResolver, client.clock,
		)
		if err == nil && reference != *expectedR3Reference {
			err = errors.New("Budget step-up Resource token changed the R3 reference")
		}
		if err == nil {
			declarations, parseErr := parseBudgetUnitDeclarations(metadata.BudgetUnits)
			if parseErr != nil {
				err = parseErr
			} else if declarationErr := budgets.ValidateDeclaredValue(declarations, offer); declarationErr != nil {
				err = declarationErr
			}
		}
	} else if carriesBudget {
		if expectedR3Reference != nil {
			return BudgetAuthorization{}, errors.New("Budget step-up Resource token dropped the R3 reference")
		}
		var offer budgets.Value
		challenge, offer, _, err = budgets.VerifyResourceToken(
			ctx, requirement.ResourceToken, client.keyResolver, client.clock,
		)
		if err == nil {
			declarations, parseErr := parseBudgetUnitDeclarations(metadata.BudgetUnits)
			if parseErr != nil {
				err = parseErr
			} else if declarationErr := budgets.ValidateDeclaredValue(declarations, offer); declarationErr != nil {
				err = declarationErr
			}
		}
	} else {
		if reasonPresent {
			return BudgetAuthorization{}, errors.New("Budget-specific step-up Resource token omitted a Budget offer")
		}
		challenge, err = aauth.VerifyResourceToken(ctx, requirement.ResourceToken, client.keyResolver, client.clock)
	}
	if err != nil {
		return BudgetAuthorization{}, err
	}
	thumbprint, err := client.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return BudgetAuthorization{}, err
	}
	if challenge.Issuer != resource || challenge.DWK != aauth.ResourceDiscoveryDocument ||
		challenge.Audience != current.PersonServer || challenge.PersonServer != current.PersonServer ||
		challenge.Subject != current.Subject || challenge.AgentJKT != thumbprint || challenge.PresentedJTI == "" ||
		challenge.MissionS256 != current.MissionS256 || challenge.Tenant != current.Tenant ||
		!equalStringPointers(challenge.Account, current.Account) ||
		!sameScopeSet(strings.Fields(challenge.Scope), strings.Fields(current.Scope)) ||
		challenge.IssuedAt < current.IssuedAt {
		return BudgetAuthorization{}, errors.New("Budget step-up Resource token does not preserve the protected call context")
	}
	return BudgetAuthorization{
		kind: budgetAuthorizationVerified, resourceToken: requirement.ResourceToken, reason: reason,
	}, nil
}
