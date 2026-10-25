package personserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/internal/r3dispatch"
	"gitlab.com/sidecat-dev/aauth-go/internal/r3fetch"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// R3Config enables immediate class and per-call R3 consent on a federated
// Person Server. Each artifact is independently fetched and sent only to its
// corresponding policy callback.
type R3Config struct {
	// Registry is the explicit immutable allowlist used to parse fetched R3
	// artifacts and operation-bearing Auth-token claims.
	Registry r3.Registry
	// Admit is required and approves the exact document URI before transport.
	// Fetches reuse the federated server's configured HTTP client; its clone
	// disables cookies and refuses redirects.
	Admit signaturekey.EgressAdmitter
	// ConsentDocument is required and receives verified Core context plus the
	// exact typed R3 reference and document.
	ConsentDocument func(context.Context, AuthorizationRequest, r3.Reference, r3.Document) error
	// ConsentProposal receives verified Core context plus one exact per-call
	// proposal. A proposal is refused when this callback is nil; class-document
	// consent continues to use ConsentDocument.
	ConsentProposal func(context.Context, AuthorizationRequest, r3.Reference, r3.Proposal) error
	// MaximumDocumentBytes defaults to 1 MiB when zero.
	MaximumDocumentBytes int64
	// FetchTimeout defaults to 10 seconds when zero.
	FetchTimeout time.Duration
}

// DirectR3Config enables immediate class-document R3 authorization on a
// three-party Person Server. It is separate from federated R3 consent because
// this Person Server selects the grant, signs the Auth token, and retains the
// issuance itself. Mission-bound issuance additionally requires the configured
// MissionStore to implement MissionR3IssuanceStore. It does not compose with
// deferred authorization, per-call proposals, sub-agents, or call chaining.
type DirectR3Config struct {
	// Registry is the required immutable allowlist used to parse fetched R3
	// documents and construct operation-bearing Auth-token claims.
	Registry r3.Registry
	// HTTPClient is required. The fetcher clones it, disables cookies, refuses
	// redirects, and leaves the caller's client unchanged.
	HTTPClient *http.Client
	// Admit is required and approves the exact document URI before transport.
	Admit signaturekey.EgressAdmitter
	// AuthorizeDocument receives verified Core context plus the exact class
	// document and returns the Core and R3 grant selected by policy.
	AuthorizeDocument func(
		context.Context,
		AuthorizationRequest,
		r3.Reference,
		r3.Document,
	) (DirectR3Decision, error)
	// Issuances atomically retains the mandatory R3 audit facts before the token
	// is returned.
	Issuances r3.IssuanceStore
	// MaximumDocumentBytes defaults to 1 MiB when zero.
	MaximumDocumentBytes int64
	// FetchTimeout defaults to 10 seconds when zero.
	FetchTimeout time.Duration
}

// DirectR3Decision selects Core scopes and lifetime plus an R3 grant proven
// against the exact document passed to AuthorizeDocument.
type DirectR3Decision struct {
	Scopes   []string
	Lifetime time.Duration
	Grant    r3.Grant
	// Budget is required when the verified Resource token carried a Budget
	// offer and must narrow that offer without changing denomination.
	Budget *budgets.Value
}

type r3Config struct {
	registry          r3.Registry
	artifacts         *r3fetch.Client
	consentDocument   func(context.Context, AuthorizationRequest, r3.Reference, r3.Document) error
	consentProposal   func(context.Context, AuthorizationRequest, r3.Reference, r3.Proposal) error
	authorizeDocument func(
		context.Context,
		AuthorizationRequest,
		r3.Reference,
		r3.Document,
	) (DirectR3Decision, error)
	issuances r3.IssuanceStore
}

type verifiedR3 struct {
	reference     r3.Reference
	document      r3.Document
	proposal      r3.Proposal
	exactArtifact []byte
	kind          r3.ArtifactKind
}

type invalidR3ArtifactError struct{ cause error }

func (failure *invalidR3ArtifactError) Error() string { return failure.cause.Error() }
func (failure *invalidR3ArtifactError) Unwrap() error { return failure.cause }

func isInvalidR3Artifact(err error) bool {
	var failure *invalidR3ArtifactError
	return errors.As(err, &failure)
}

func newR3Config(
	config *R3Config,
	httpClient *http.Client,
	signingKey jose.SigningKey,
	issuer string,
	clock aauth.Clock,
) (*r3Config, error) {
	if config == nil {
		return nil, nil
	}
	if config.ConsentDocument == nil {
		return nil, errors.New("personserver: R3 document consent policy is required")
	}
	artifacts, err := r3fetch.New(r3fetch.Config{
		Registry:   config.Registry,
		HTTPClient: httpClient, SigningKey: signingKey,
		Issuer: issuer, DiscoveryDocument: aauth.PersonDiscoveryDocument,
		Clock: clock, Admit: config.Admit,
		MaximumDocumentBytes: config.MaximumDocumentBytes,
		Timeout:              config.FetchTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("personserver: R3: %w", err)
	}
	return &r3Config{
		registry: config.Registry, artifacts: artifacts, consentDocument: config.ConsentDocument,
		consentProposal: config.ConsentProposal,
	}, nil
}

func newDirectR3Config(
	config *DirectR3Config,
	signingKey jose.SigningKey,
	issuer string,
	clock aauth.Clock,
) (*r3Config, error) {
	if config == nil {
		return nil, nil
	}
	if config.HTTPClient == nil {
		return nil, errors.New("personserver: direct R3 HTTP client is required")
	}
	if config.AuthorizeDocument == nil {
		return nil, errors.New("personserver: direct R3 document authorization policy is required")
	}
	if config.Issuances == nil {
		return nil, errors.New("personserver: direct R3 issuance store is required")
	}
	artifacts, err := r3fetch.New(r3fetch.Config{
		Registry:   config.Registry,
		HTTPClient: config.HTTPClient, SigningKey: signingKey,
		Issuer: issuer, DiscoveryDocument: aauth.PersonDiscoveryDocument,
		Clock: clock, Admit: config.Admit,
		MaximumDocumentBytes: config.MaximumDocumentBytes,
		Timeout:              config.FetchTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("personserver: direct R3: %w", err)
	}
	return &r3Config{
		registry: config.Registry, artifacts: artifacts,
		authorizeDocument: config.AuthorizeDocument,
		issuances:         config.Issuances,
	}, nil
}

func (server *Server) verifyResourceTokenForAuthorization(
	ctx context.Context,
	compact string,
	clock aauth.Clock,
) (aauth.ResourceTokenClaims, *verifiedR3, *budgets.Value, *budgets.ConsumptionRecord, error) {
	carriesR3, err := r3dispatch.TokenCarriesClaims(compact)
	if err != nil {
		return aauth.ResourceTokenClaims{}, nil, nil, nil, err
	}
	carriesBudget, err := budgets.TokenCarriesClaims(compact)
	if err != nil {
		return aauth.ResourceTokenClaims{}, nil, nil, nil, err
	}
	if carriesR3 && carriesBudget {
		if server.r3 == nil {
			return aauth.ResourceTokenClaims{}, nil, nil, nil, errors.New("personserver: combined R3 and Budget resource token requires R3 authorization")
		}
		claims, reference, offer, consumed, err := r3.VerifyBudgetResourceToken(
			ctx, server.r3.registry, compact, server.keyResolver, clock,
		)
		if err != nil {
			return aauth.ResourceTokenClaims{}, nil, nil, nil, err
		}
		return claims, &verifiedR3{reference: reference}, cloneBudgetValue(&offer), cloneConsumptionRecord(consumed), nil
	}
	if carriesBudget {
		if server.resolveBudgetResourceUnits == nil {
			return aauth.ResourceTokenClaims{}, nil, nil, nil, errors.New("personserver: Budget authorization is not configured")
		}
		claims, offer, consumed, err := budgets.VerifyResourceToken(ctx, compact, server.keyResolver, clock)
		if err != nil {
			return aauth.ResourceTokenClaims{}, nil, nil, nil, err
		}
		return claims, nil, cloneBudgetValue(&offer), cloneConsumptionRecord(consumed), nil
	}
	if !carriesR3 {
		claims, err := aauth.VerifyResourceToken(ctx, compact, server.keyResolver, clock)
		return claims, nil, nil, nil, err
	}
	if server.r3 == nil {
		return aauth.ResourceTokenClaims{}, nil, nil, nil, errors.New("personserver: R3 resource token is not supported")
	}
	claims, reference, err := r3.VerifyResourceToken(ctx, compact, server.keyResolver, clock)
	if err != nil {
		return aauth.ResourceTokenClaims{}, nil, nil, nil, err
	}
	return claims, &verifiedR3{reference: reference}, nil, nil, nil
}

func (server *Server) verifyR3BudgetAccessResult(
	ctx context.Context,
	compact string,
	verified *verifiedR3,
) (aauth.AuthTokenClaims, budgets.Value, error) {
	if verified == nil || verified.kind != r3.ArtifactDocument {
		return aauth.AuthTokenClaims{}, budgets.Value{}, errors.New("personserver: class R3 context is required for a Budget result")
	}
	claims, reference, operations, grant, err := r3.VerifyBudgetAuthToken(
		ctx, server.r3.registry, compact, server.keyResolver, server.clock,
	)
	if err != nil {
		return aauth.AuthTokenClaims{}, budgets.Value{}, err
	}
	if reference != verified.reference {
		return aauth.AuthTokenClaims{}, budgets.Value{}, errors.New("personserver: Access Server changed the R3 document reference")
	}
	if err := r3.ValidateDocumentAccount(verified.document, claims.Account); err != nil {
		return aauth.AuthTokenClaims{}, budgets.Value{}, fmt.Errorf("personserver: Access Server R3 account: %w", err)
	}
	if _, err := r3.NewGrant(operations.GrantedOperations(), verified.document); err != nil {
		return aauth.AuthTokenClaims{}, budgets.Value{}, fmt.Errorf("personserver: Access Server R3 Budget authorization: %w", err)
	}
	return claims, grant, nil
}

func (server *Server) fetchR3Artifact(
	ctx context.Context,
	verified *verifiedR3,
	account *string,
) error {
	if verified == nil || server.r3 == nil {
		return errors.New("personserver: R3 context is incomplete")
	}
	artifact, err := server.r3.artifacts.FetchArtifact(ctx, verified.reference)
	if err != nil {
		if r3fetch.IsDocumentError(err) {
			return &invalidR3ArtifactError{cause: err}
		}
		return err
	}
	if document, ok := artifact.Document(); ok {
		if err := r3.ValidateDocumentAccount(document, account); err != nil {
			return &invalidR3ArtifactError{cause: fmt.Errorf("personserver: R3 account: %w", err)}
		}
		verified.document = document
		verified.exactArtifact = artifact.ExactBytes()
		verified.kind = r3.ArtifactDocument
		return nil
	}
	if proposal, ok := artifact.Proposal(); ok {
		if err := r3.ValidateProposalAccount(proposal, account); err != nil {
			return &invalidR3ArtifactError{cause: fmt.Errorf("personserver: R3 proposal account: %w", err)}
		}
		verified.proposal = proposal
		verified.exactArtifact = artifact.ExactBytes()
		verified.kind = r3.ArtifactProposal
		return nil
	}
	return &invalidR3ArtifactError{cause: errors.New("personserver: R3 artifact is unclassified")}
}

func (server *Server) verifyR3AccessResult(
	ctx context.Context,
	compact string,
	verified *verifiedR3,
) (aauth.AuthTokenClaims, error) {
	if verified == nil {
		return aauth.AuthTokenClaims{}, errors.New("personserver: R3 context is required")
	}
	switch verified.kind {
	case r3.ArtifactDocument:
		claims, reference, operations, err := r3.VerifyAuthTokenClaims(
			ctx, server.r3.registry, compact, server.keyResolver, server.clock,
		)
		if err != nil {
			return aauth.AuthTokenClaims{}, err
		}
		if reference != verified.reference {
			return aauth.AuthTokenClaims{}, errors.New("personserver: Access Server changed the R3 document reference")
		}
		if err := r3.ValidateDocumentAccount(verified.document, claims.Account); err != nil {
			return aauth.AuthTokenClaims{}, fmt.Errorf("personserver: Access Server R3 account: %w", err)
		}
		if _, err := r3.NewAuthorization(
			operations.GrantedOperations(), operations.PerCallOperations(), verified.document,
		); err != nil {
			return aauth.AuthTokenClaims{}, fmt.Errorf("personserver: Access Server R3 authorization: %w", err)
		}
		return claims, nil
	case r3.ArtifactProposal:
		claims, _, _, err := r3.VerifyPerCallAuthToken(
			ctx, server.r3.registry, compact, server.keyResolver, server.clock,
			verified.reference, verified.exactArtifact,
		)
		if err != nil {
			return aauth.AuthTokenClaims{}, fmt.Errorf("personserver: Access Server R3 proposal result: %w", err)
		}
		return claims, nil
	default:
		return aauth.AuthTokenClaims{}, errors.New("personserver: R3 artifact is unclassified")
	}
}

func (server *Server) consentR3(
	ctx context.Context,
	request AuthorizationRequest,
	verified *verifiedR3,
) error {
	if server == nil || server.r3 == nil || verified == nil {
		return errors.New("personserver: R3 consent context is incomplete")
	}
	switch verified.kind {
	case r3.ArtifactDocument:
		if server.r3.consentDocument == nil {
			return errors.New("personserver: R3 document consent policy is required")
		}
		return server.r3.consentDocument(ctx, request, verified.reference, verified.document)
	case r3.ArtifactProposal:
		if server.r3.consentProposal == nil {
			return errors.New("personserver: R3 proposal consent policy is required")
		}
		return server.r3.consentProposal(ctx, request, verified.reference, verified.proposal)
	default:
		return errors.New("personserver: R3 artifact is unclassified")
	}
}

func cloneAuthorizationAccount(account *string) *string {
	if account == nil {
		return nil
	}
	cloned := *account
	return &cloned
}
