package resource

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/r3"
)

var (
	// ErrBudgetInsufficient reports that a metered request's fixed cost is
	// greater than the unreserved remainder of the signed grant.
	ErrBudgetInsufficient = errors.New("resource: request cost exceeds remaining Budget")
	// ErrBudgetExhausted reports that the signed grant has no remainder.
	ErrBudgetExhausted = errors.New("resource: Budget is exhausted")
	// ErrBudgetConflict reports reuse of one auth-token identity with a
	// different signed grant or person context.
	ErrBudgetConflict = errors.New("resource: Budget token context conflicts with retained state")
)

// BudgetOfferRequest is the authenticated, typed input to an optional host
// offer policy. Requested has already been checked against a declared unit
// and capped at that declaration's Maximum. The policy may lower it or select
// another declared denomination.
type BudgetOfferRequest struct {
	Person        PersonIdentity
	PersonContext PersonContext
	Scope         []string
	Requested     budgets.Value
}

// BudgetInitialOfferRequest is the verified context for sizing a Budget when
// the Agent first calls the Resource with a Person token rather than making a
// proactive authorization request. The host selects one declared unit and
// amount; the library does not guess among declarations.
type BudgetInitialOfferRequest struct {
	Request       *http.Request
	Person        PersonIdentity
	PersonContext PersonContext
	Scope         []string
}

// BudgetLineage is the Resource-side record needed to construct a later
// Budget step-up without recovering Person-token identity from an Auth token.
// RetainLineage receives it after token minting and before token release. A
// host with multiple live matching records must use its own policy or refuse
// an ambiguous challenge; the protocol supplies no Auth-token lookup binding.
type BudgetLineage struct {
	ResourceToken aauth.TokenReference
	Person        PersonIdentity
	PersonContext PersonContext
	PresentedJTI  string
	AgentJKT      string
	Scope         []string
	Offer         budgets.Value
	IssuedAt      int64
	ExpiresAt     int64
}

// BudgetCostRequest is the complete verified input to fixed-price policy.
// Request and Principal are independent copies. Grant supplies the signed
// denomination and cap in which Cost must be returned.
type BudgetCostRequest struct {
	Request   *http.Request
	Principal AuthPrincipal
	Grant     budgets.Value
}

// BudgetChallengeRequest asks the host to use its retained Person-token
// lineage to mint a fresh Budget Resource token. The Resource verifies the
// returned token's observable context before exposing it, but cannot prove
// freshness or select presented_jti from the Auth token alone. The host must
// not reconstruct or guess that identifier.
type BudgetChallengeRequest struct {
	Token     aauth.TokenReference
	Principal AuthPrincipal
	Grant     budgets.Value
	Remaining int64
	Required  int64
	Reason    budgets.Reason
	// R3Reference is present when the refused Auth token also authorizes one
	// R3 class document. A replacement Resource token must preserve it.
	R3Reference *r3.Reference
}

// BudgetCharge is the metering binding for one atomic fixed-price consequence.
// It carries the signed grant and person-accounting context, not the complete
// Auth-token authorization. Store implementations bind Token to this metering
// context, enforce the per-token cap, and atomically post Cost to the
// (PersonServer, Subject, Audience) ledger.
type BudgetCharge struct {
	Token        aauth.TokenReference
	PersonServer string
	Subject      string
	Audience     string
	MissionS256  string
	Tenant       string
	Account      *string
	Grant        budgets.Value
	Cost         int64
}

// BudgetChargeResult is the definitive result of one BudgetStore.Charge.
// Cost must equal the requested charge on success. Remaining is net of the
// committed charge, or the unchanged remainder on an insufficiency refusal.
type BudgetChargeResult struct {
	Cost      int64
	Remaining int64
}

// BudgetStore owns the Resource's atomic hard-cap and person-ledger
// consequence. Charge must be linearizable. It must either commit Cost to the
// token and person ledgers together and return the new remainder, or commit
// neither and return ErrBudgetInsufficient/ErrBudgetExhausted with the current
// remainder. A token reference already bound to different Grant or context
// returns ErrBudgetConflict without changing state. Other errors must not
// commit a charge.
type BudgetStore interface {
	Charge(context.Context, BudgetCharge) (BudgetChargeResult, error)
}

// BudgetConfig enables the first fixed-price Budget profile on a direct
// Person-Server-authorized Resource. Units are advertised in Resource
// metadata. InitialOffer sizes an optional reactive first-call challenge;
// Offer may lower a valid proactive request or select another declared
// denomination. Cost returns the exact, finite charge before application
// dispatch. Challenge requires the host to select retained Person-token
// lineage and mint a fresh Resource token for a hard-cap refusal; the library
// verifies context but cannot independently prove freshness.
type BudgetConfig struct {
	Units         []budgets.UnitDeclaration
	InitialOffer  func(context.Context, BudgetInitialOfferRequest) (budgets.Value, error)
	Offer         func(context.Context, BudgetOfferRequest) (budgets.Value, error)
	RetainLineage func(context.Context, BudgetLineage) error
	Cost          func(context.Context, BudgetCostRequest) (int64, error)
	Store         BudgetStore
	Challenge     func(context.Context, BudgetChallengeRequest) (string, error)
}

type budgetConfig struct {
	units        []budgets.UnitDeclaration
	byName       map[string]budgets.UnitDeclaration
	initialOffer func(context.Context, BudgetInitialOfferRequest) (budgets.Value, error)
	offer        func(context.Context, BudgetOfferRequest) (budgets.Value, error)
	retain       func(context.Context, BudgetLineage) error
	cost         func(context.Context, BudgetCostRequest) (int64, error)
	store        BudgetStore
	challenge    func(context.Context, BudgetChallengeRequest) (string, error)
}

type budgetOfferPolicyError struct{ cause error }

func (failure *budgetOfferPolicyError) Error() string { return failure.cause.Error() }
func (failure *budgetOfferPolicyError) Unwrap() error { return failure.cause }

func validateBudgetConfig(config *BudgetConfig, topology authorizationTopology) (*budgetConfig, error) {
	if config == nil {
		return nil, nil
	}
	if topology != authorizationTopologyPersonServer {
		return nil, errors.New("aauth: fixed-price Resource Budget requires direct Person Server authorization")
	}
	if len(config.Units) == 0 {
		return nil, errors.New("aauth: Resource Budget requires at least one declared unit")
	}
	if config.Cost == nil {
		return nil, errors.New("aauth: Resource Budget fixed-cost policy is required")
	}
	if config.RetainLineage == nil {
		return nil, errors.New("aauth: Resource Budget lineage retention is required")
	}
	if config.Store == nil {
		return nil, errors.New("aauth: Resource Budget store is required")
	}
	if config.Challenge == nil {
		return nil, errors.New("aauth: Resource Budget challenge issuer is required")
	}
	validated := &budgetConfig{
		units:        make([]budgets.UnitDeclaration, 0, len(config.Units)),
		byName:       make(map[string]budgets.UnitDeclaration, len(config.Units)),
		initialOffer: config.InitialOffer, offer: config.Offer, retain: config.RetainLineage,
		cost: config.Cost, store: config.Store, challenge: config.Challenge,
	}
	if err := budgets.ValidateUnitDeclarations(config.Units); err != nil {
		return nil, fmt.Errorf("aauth: Resource Budget units: %w", err)
	}
	for _, declaration := range config.Units {
		if err := budgets.ValidateFeedbackUnit(declaration.Unit()); err != nil {
			return nil, fmt.Errorf("aauth: Resource Budget unit %q: %w", declaration.Unit().Name(), err)
		}
		maximum, present := declaration.Maximum()
		if !present {
			return nil, fmt.Errorf(
				"aauth: fixed-price Resource Budget unit %q requires a metadata maximum",
				declaration.Unit().Name(),
			)
		}
		_ = maximum
		validated.units = append(validated.units, declaration)
		validated.byName[declaration.Unit().Name()] = declaration
	}
	return validated, nil
}

func (config *budgetConfig) initialOfferFor(
	ctx context.Context,
	request *http.Request,
	person aauth.PersonTokenClaims,
	scopes []string,
) (budgets.Value, bool, error) {
	if config == nil || config.initialOffer == nil {
		return budgets.Value{}, false, nil
	}
	policyRequest, finish, err := cloneScopePolicyRequest(request)
	if err != nil {
		return budgets.Value{}, false, err
	}
	offered, err := config.initialOffer(ctx, BudgetInitialOfferRequest{
		Request: policyRequest,
		Person:  PersonIdentity{Issuer: person.Issuer, Subject: person.Subject},
		PersonContext: PersonContext{
			MissionS256: person.MissionS256,
			Tenant:      person.Tenant,
		},
		Scope: append([]string(nil), scopes...),
	})
	finishErr := finish()
	if err != nil {
		return budgets.Value{}, false, &budgetOfferPolicyError{cause: err}
	}
	if finishErr != nil {
		return budgets.Value{}, false, finishErr
	}
	if err := budgets.ValidateDeclaredValue(config.units, offered); err != nil {
		return budgets.Value{}, false, &budgetOfferPolicyError{cause: fmt.Errorf("Resource initial Budget offer policy: %w", err)}
	}
	return offered, true, nil
}

func (config *budgetConfig) offerFor(
	ctx context.Context,
	person aauth.PersonTokenClaims,
	scopes []string,
	raw []byte,
) (budgets.Value, error) {
	requested, err := budgets.ParseValueJSON(raw)
	if err != nil {
		return budgets.Value{}, err
	}
	declaration, declared := config.byName[requested.Unit().Name()]
	if !declared || !declaration.Unit().Equal(requested.Unit()) {
		return budgets.Value{}, fmt.Errorf(
			"budgets: unit %q/%d is not declared by the Resource",
			requested.Unit().Name(), requested.Unit().Decimals(),
		)
	}
	maximum, _ := declaration.Maximum()
	amount := requested.Amount()
	if amount > maximum {
		amount = maximum
	}
	bounded, err := budgets.NewValue(amount, declaration.Unit())
	if err != nil {
		return budgets.Value{}, err
	}
	if config.offer == nil {
		return bounded, nil
	}
	policyInput := BudgetOfferRequest{
		Person: PersonIdentity{Issuer: person.Issuer, Subject: person.Subject},
		PersonContext: PersonContext{
			MissionS256: person.MissionS256,
			Tenant:      person.Tenant,
		},
		Scope: append([]string(nil), scopes...), Requested: bounded,
	}
	offered, err := config.offer(ctx, policyInput)
	if err != nil {
		return budgets.Value{}, &budgetOfferPolicyError{cause: err}
	}
	if err := budgets.ValidateDeclaredValue(config.units, offered); err != nil {
		return budgets.Value{}, &budgetOfferPolicyError{cause: fmt.Errorf("Resource Budget offer policy: %w", err)}
	}
	if offered.Unit().Equal(bounded.Unit()) {
		if err := budgets.ValidateNarrowing(bounded, offered); err != nil {
			return budgets.Value{}, &budgetOfferPolicyError{cause: fmt.Errorf("Resource Budget offer policy: %w", err)}
		}
	}
	return offered, nil
}

func (config *budgetConfig) declared(value budgets.Value) bool {
	return budgets.ValidateDeclaredValue(config.units, value) == nil
}

func cloneBudgetAccount(account *string) *string {
	if account == nil {
		return nil
	}
	value := *account
	return &value
}

func sameBudgetAccount(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
