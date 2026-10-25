package resource

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

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
	// ErrUsageMixedUnit reports that one usage answer would mix denominations.
	// The usage response names one unit and the draft defines no selector.
	ErrUsageMixedUnit = errors.New("resource: usage figures span more than one Budget unit")
)

// BudgetOfferRequest is the authenticated, typed input to an optional host
// offer policy. Requested has already been checked against a declared unit
// and capped at that declaration's Maximum. Account, when present, has already
// been accepted by the Resource's account policy. The offer policy may lower
// the value or select another declared denomination.
type BudgetOfferRequest struct {
	Person        PersonIdentity
	PersonContext PersonContext
	Account       *string
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

// BudgetLineage is the Resource-side record of the initial Budget
// authorization request. PresentedJTI is the jti of the token presented on
// that request; a later step-up names the refused Auth token instead.
// RetainLineage receives it after token minting and before token release. A
// Account is the Resource-owned account selected on the authorization request.
// A host with multiple live matching records must use its own policy or refuse
// an ambiguous challenge; the protocol supplies no Auth-token lookup binding.
type BudgetLineage struct {
	ResourceToken aauth.TokenReference
	Person        PersonIdentity
	PersonContext PersonContext
	Account       *string
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

// BudgetChallengeRequest asks the host to mint a fresh Budget Resource token
// for a step-up. The agent presented the refused Auth token, so the fresh
// token's presented_jti is Token.JTI. The Resource verifies that and the
// returned token's other observable context before exposing it, but cannot
// prove freshness.
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
	// AgentJKT is the confirmation thumbprint of the presented auth token.
	// ChargedAt is when this charge was metered. Neither field is part of the
	// token-binding identity: a later charge for the same token may carry a
	// newer time, and stores compare the grant and person context only.
	AgentJKT  string
	ChargedAt time.Time
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
// commit a charge. A zero Cost observes the current remainder without spending;
// it may establish the token binding. An exhausted zero-cost observation may
// return ErrBudgetExhausted with Cost and Remaining both zero.
type BudgetStore interface {
	Charge(context.Context, BudgetCharge) (BudgetChargeResult, error)
}

// BudgetUsageCaller is the signed server asking for usage counters.
type BudgetUsageCaller struct {
	// Identifier is the Signature-Key id, which the response echoes as aud.
	Identifier string
	// Document is aauth-person.json or aauth-access.json.
	Document string
}

// BudgetUsageQuery is one usage-endpoint question. A Person Server sees
// postings whose auth-token iss or ps is the caller. An Access Server sees
// postings it issued, and a scope key also requires PersonServer. Tenant and
// mission totals stay inside that person-server namespace. Calendar counters
// use UTC boundaries: day at 00:00, ISO week at Monday 00:00, and the current
// month and year. A counter that cannot be represented within the 15-digit
// limit is omitted; all_time failing that limit omits the usage object.
// A JKT is omitted rather than reported as zero when it was never seen or its
// last metered charge is more than 24 hours before AsOf. ChargedAt zero is not
// pruned. A zero cost that was metered is a real zero.
type BudgetUsageQuery struct {
	Caller       BudgetUsageCaller
	AsOf         time.Time
	Subject      string
	Tenant       string
	MissionS256  string
	PersonServer string
	JKTs         []string
}

// BudgetUsageResult is the aggregate a usage store can answer. HasUnit is
// false when no posting matched. ScopeRecognized is false for a scope key the
// caller has not metered, which the endpoint reports by omitting usage.
// A false *OK field means that counter overflowed the 15-digit limit.
// JKTs contains only thumbprints the store can answer.
type BudgetUsageResult struct {
	Unit            budgets.Unit
	HasUnit         bool
	ScopeRecognized bool
	AllTime         int64
	AllTimeOK       bool
	Day             int64
	DayOK           bool
	Week            int64
	WeekOK          bool
	Month           int64
	MonthOK         bool
	Year            int64
	YearOK          bool
	JKTs            map[string]int64
}

// BudgetUsageStore is the optional usage-query half of a Budget store. A
// Resource advertises usage_endpoint and serves POST /usage only when its
// BudgetStore also implements this interface.
type BudgetUsageStore interface {
	QueryUsage(context.Context, BudgetUsageQuery) (BudgetUsageResult, error)
}

// BudgetConfig enables the fixed-price Budget profile on an authorized
// Resource. Units are advertised in Resource
// metadata. InitialOffer sizes an optional reactive first-call challenge;
// Offer may lower a valid proactive request or select another declared
// denomination. Cost returns the exact, finite charge before application
// dispatch. Challenge requires the host to select retained Person-token
// lineage and mint a fresh Resource token for a hard-cap refusal; the library
// verifies context but cannot independently prove freshness.
type BudgetConfig struct {
	// Metered selects protected routes that require a signed Budget grant.
	// Nil meters every protected route. An unmetered route charges nothing.
	// The callback receives an independent request copy after token and proof
	// verification. It does not select initial authorization offers.
	Metered       func(*http.Request) bool
	Units         []budgets.UnitDeclaration
	InitialOffer  func(context.Context, BudgetInitialOfferRequest) (budgets.Value, error)
	Offer         func(context.Context, BudgetOfferRequest) (budgets.Value, error)
	RetainLineage func(context.Context, BudgetLineage) error
	Cost          func(context.Context, BudgetCostRequest) (int64, error)
	Store         BudgetStore
	Challenge     func(context.Context, BudgetChallengeRequest) (string, error)
}

type budgetConfig struct {
	metered      func(*http.Request) bool
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
	if topology != authorizationTopologyPersonServer && topology != authorizationTopologyFederated {
		return nil, errors.New("aauth: fixed-price Resource Budget requires an authorization topology")
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
		metered:      config.Metered,
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
	account *string,
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
		Account: cloneBudgetAccount(account),
		Scope:   append([]string(nil), scopes...), Requested: bounded,
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
