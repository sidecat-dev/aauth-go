package resource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// R3ReleaseConfig lets a Resource run a per-call operation before it seeks
// approval, and ask the person to approve release of the result instead of
// execution (R3 Approving Release Rather Than Execution). It applies only to
// a call the Resource holds under 202 deferred delivery, so the agent's flow
// is unchanged: the held call runs at once, its response is retained, and
// the first poll with the per-call Auth token receives that response. The
// call never runs again, and a result whose release is never approved is
// never sent.
//
// Running first is allowed only where nothing outside the result changes
// when the call runs. The Resource itself refuses it on a route its Budget
// profile meters and, unless MeterRelease is set, for an operation its
// definition annotates budget:true, because there running is the metered
// event and approval must precede it. Eligible must refuse the other cases
// only the host knows: a call whose running is audited or billed, or that
// calls another party.
type R3ReleaseConfig struct {
	// Eligible reports whether this call may run before approval.
	Eligible func(context.Context, r3.Invocation) (bool, error)
	// DescribeResult describes a call that has run, for the proposal.
	DescribeResult func(context.Context, R3ReleaseRequest) (R3ReleaseDescription, error)
	// MeterRelease says this Resource meters the release of a held result,
	// not the execution, of an operation its definition annotates
	// budget:true. Such an operation may then run first, and DescribeResult
	// must state its Cost. The proposal's Resource token offers exactly that
	// cost as its budget, the per-call Auth token carries the grant, and the
	// poll that releases the result draws the cost down from that token once
	// (Budgets Deferred Delivery). A per-call token whose budget does not
	// cover the cost is refused with 403 and AAuth-Budget stating required,
	// and the result stays held. A declined release meters nothing. It
	// requires the Resource's Budget profile.
	MeterRelease bool
}

// R3ReleaseRequest is a call the Resource has run before approval. Response
// is what the application answered; it is released only on approval.
type R3ReleaseRequest struct {
	Invocation r3.Invocation
	Account    *string
	Response   HeldResponse
}

// R3ReleaseDescription is the Resource's release proposal for a call that has
// run. Parameters must match the presented values. Result is the proposal's
// result member, a JSON object of Resource-defined members such as how many
// records came back and which categories of data they hold; the response
// itself is not carried. The proposal's display is Display with Detail after
// the r3.ReleaseAction section, which states that the operation has run and
// that what is approved is release of its result.
//
// Cost is what releasing the result draws down, in one of the Resource's
// declared denominations. It is set exactly for an operation annotated
// budget:true under R3ReleaseConfig.MeterRelease, and nil otherwise.
type R3ReleaseDescription struct {
	Parameters r3.Parameters
	Result     json.RawMessage
	Display    r3.Display
	Detail     string
	Cost       *budgets.Value
}

type r3ReleaseConfig struct {
	eligible       func(context.Context, r3.Invocation) (bool, error)
	describeResult func(context.Context, R3ReleaseRequest) (R3ReleaseDescription, error)
	meterRelease   bool
}

func validateR3ReleaseConfig(config *R3ReleaseConfig) (*r3ReleaseConfig, error) {
	if config == nil {
		return nil, nil
	}
	if config.Eligible == nil || config.DescribeResult == nil {
		return nil, errors.New("aauth: Resource R3 release gating requires an eligibility policy and a result description")
	}
	return &r3ReleaseConfig{
		eligible: config.Eligible, describeResult: config.DescribeResult, meterRelease: config.MeterRelease,
	}, nil
}

// releaseEligible decides whether a held per-call invocation runs before
// approval: the host policy must allow it, the route must not be metered by
// the Budget profile, and the operation must not carry budget:true unless the
// Resource meters its release. metered reports a release whose cost is drawn
// down when it is released.
func (server *Server) releaseEligible(
	request *http.Request,
	invocation r3.Invocation,
) (eligible bool, metered bool, err error) {
	release := server.r3.perCall.release
	if release == nil {
		return false, false, nil
	}
	operation := invocation.Operation()
	vocabulary, ok := server.r3.vocabularies[operation.Vocabulary()]
	if !ok {
		return false, false, fmt.Errorf("aauth: R3 vocabulary %q is not configured", operation.Vocabulary())
	}
	hints, present, err := vocabulary.definition.HintsFor(operation)
	if err != nil {
		return false, false, err
	}
	if present {
		if budgeted, set := hints.Budget(); set && budgeted {
			if !release.meterRelease {
				return false, false, nil
			}
			metered = true
		}
	}
	if server.budget != nil {
		meteredRoute := true
		if server.budget.metered != nil {
			policyRequest, finish, err := cloneScopePolicyRequest(request)
			if err != nil {
				return false, false, err
			}
			meteredRoute = server.budget.metered(policyRequest)
			if err := finish(); err != nil {
				return false, false, err
			}
		}
		if meteredRoute {
			return false, false, nil
		}
	}
	eligible, err = release.eligible(request.Context(), invocation)
	if err != nil {
		return false, false, fmt.Errorf("aauth: R3 release eligibility: %w", err)
	}
	return eligible, metered && eligible, nil
}

// runForRelease runs the held call under the class Auth token that was
// presented on it and builds the release proposal from the result. A metered
// release returns its cost, which the proposal's Resource token offers.
func (server *Server) runForRelease(
	ctx context.Context,
	snapshot heldRequestSnapshot,
	compact string,
	claims aauth.AuthTokenClaims,
	proof signaturekey.VerifiedRequest,
	scopes []string,
	invocation r3.Invocation,
	metered bool,
) (r3.Proposal, HeldResponse, *budgets.Value, error) {
	response := server.executeHeldInvocation(snapshot, compact, claims, proof.PublicKey(), proof.VerifiedAt(), scopes)
	description, err := server.r3.perCall.release.describeResult(ctx, R3ReleaseRequest{
		Invocation: invocation, Account: cloneAuthorizationAccount(claims.Account),
		Response: cloneHeldResponse(response),
	})
	if err != nil {
		return r3.Proposal{}, HeldResponse{}, nil, fmt.Errorf("R3 release description: %w", err)
	}
	if description.Result == nil {
		return r3.Proposal{}, HeldResponse{}, nil, errors.New("R3 release description has no result")
	}
	if matches, err := description.Parameters.Matches(invocation.PresentedParameters()); err != nil || !matches {
		if err == nil {
			err = errors.New("release parameters do not match the concrete call")
		}
		return r3.Proposal{}, HeldResponse{}, nil, fmt.Errorf("R3 release description: %w", err)
	}
	cost, err := server.releaseCost(description.Cost, metered)
	if err != nil {
		return r3.Proposal{}, HeldResponse{}, nil, fmt.Errorf("R3 release description: %w", err)
	}
	display, err := r3.NewReleaseProposalDisplay(description.Display, description.Detail)
	if err != nil {
		return r3.Proposal{}, HeldResponse{}, nil, fmt.Errorf("R3 release display: %w", err)
	}
	proposal, err := r3.NewProposal(invocation.Operation(), description.Parameters, r3.ProposalOptions{
		Account: cloneAuthorizationAccount(claims.Account), Result: description.Result, Display: &display,
	})
	if err != nil {
		return r3.Proposal{}, HeldResponse{}, nil, fmt.Errorf("construct R3 release proposal: %w", err)
	}
	return proposal, response, cost, nil
}

// releaseCost checks the cost a release description states: a positive value
// in a declared denomination for a metered release, and none otherwise.
func (server *Server) releaseCost(cost *budgets.Value, metered bool) (*budgets.Value, error) {
	switch {
	case !metered && cost != nil:
		return nil, errors.New("an unmetered release states a cost")
	case !metered:
		return nil, nil
	case cost == nil:
		return nil, errors.New("a metered release states no cost")
	case cost.Amount() <= 0:
		return nil, errors.New("a metered release cost must be positive")
	}
	if err := budgets.ValidateDeclaredValue(server.budget.units, *cost); err != nil {
		return nil, fmt.Errorf("metered release cost: %w", err)
	}
	offered := *cost
	return &offered, nil
}

// heldRelease returns the retained response of a release-gated held call, or
// false for a call held for execution. The proposal's result member and the
// retained response must agree: a release proposal without its response
// cannot be completed, and must never run the call again.
func (server *Server) heldRelease(invocation HeldInvocation) (HeldResponse, bool, error) {
	if invocation.R3PerCall == nil {
		return HeldResponse{}, false, nil
	}
	proposal, err := server.r3.registry.ParseReferencedProposal(invocation.R3PerCall.Reference, invocation.R3PerCall.ExactProposal)
	if err != nil {
		return HeldResponse{}, false, retainedR3State(fmt.Errorf("parse held R3 proposal: %w", err))
	}
	_, released := proposal.Result()
	switch {
	case released && invocation.R3PerCall.Release == nil:
		return HeldResponse{}, false, retainedR3State(errors.New("held R3 release proposal has no retained response"))
	case !released && invocation.R3PerCall.Release != nil:
		return HeldResponse{}, false, retainedR3State(errors.New("held R3 execution proposal carries a retained response"))
	case released:
		return cloneHeldResponse(*invocation.R3PerCall.Release), true, nil
	default:
		return HeldResponse{}, false, nil
	}
}
