package accessserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/r3dispatch"
	"gitlab.com/sidecat-dev/aauth-go/internal/r3fetch"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// R3Config enables class-document and per-call proposal authorization.
// Each artifact is fetched once, classified from its exact contents, and sent
// only to the policy callback for that artifact kind.
type R3Config struct {
	// Registry is the explicit immutable allowlist used to parse fetched R3
	// artifacts and operation-bearing Auth-token claims.
	Registry r3.Registry
	// HTTPClient is required. The fetcher clones it, disables cookies, refuses
	// redirects, and leaves the caller's client unchanged.
	HTTPClient *http.Client
	// Admit is required and approves the exact document URI before transport.
	Admit signaturekey.EgressAdmitter
	// FetchTimeout defaults to 10 seconds when zero.
	FetchTimeout time.Duration
	// MaximumDocumentBytes defaults to 1 MiB when zero.
	MaximumDocumentBytes int64
	// AuthorizeDocument receives verified Core context plus the exact class
	// document and returns scope, lifetime, and operation authorization.
	AuthorizeDocument func(
		context.Context,
		AuthorizationRequest,
		r3.Reference,
		r3.Document,
	) (R3DocumentDecision, error)
	// AuthorizeProposal receives verified Core context plus one exact per-call
	// proposal. A proposal is refused when this callback is nil; class documents
	// are authorized only through AuthorizeDocument.
	AuthorizeProposal func(
		context.Context,
		AuthorizationRequest,
		r3.Reference,
		r3.Proposal,
	) (R3ProposalDecision, error)
	// Issuances is required and atomically retains the mandatory audit record
	// before the token is returned.
	Issuances r3.IssuanceStore
}

// R3DocumentDecision is the Core scope, lifetime, and operation decision for
// one exact class document. Authorization must be proven against that document.
type R3DocumentDecision struct {
	Scopes        []string
	Lifetime      time.Duration
	Authorization *r3.Authorization
}

// R3ProposalDecision is the Core scope and lifetime decision for one exact
// per-call proposal. The proposal itself determines the sole R3 operation;
// policy cannot substitute another operation or carry r3_per_call forward.
type R3ProposalDecision struct {
	Scopes   []string
	Lifetime time.Duration
}

type r3Config struct {
	registry          r3.Registry
	artifacts         *r3fetch.Client
	authorizeDocument func(
		context.Context,
		AuthorizationRequest,
		r3.Reference,
		r3.Document,
	) (R3DocumentDecision, error)
	authorizeProposal func(
		context.Context,
		AuthorizationRequest,
		r3.Reference,
		r3.Proposal,
	) (R3ProposalDecision, error)
	issuances r3.IssuanceStore
}

type verifiedR3 struct {
	reference  r3.Reference
	document   r3.Document
	proposal   r3.Proposal
	exact      []byte
	kind       r3.ArtifactKind
	vocabulary r3.VocabularyURI
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
	signingKey jose.SigningKey,
	issuer string,
	clock aauth.Clock,
) (*r3Config, error) {
	if config == nil {
		return nil, nil
	}
	if config.Issuances == nil {
		return nil, errors.New("accessserver: R3 issuance store is required")
	}
	if config.AuthorizeDocument == nil {
		return nil, errors.New("accessserver: R3 document authorization policy is required")
	}
	artifacts, err := r3fetch.New(r3fetch.Config{
		Registry:   config.Registry,
		HTTPClient: config.HTTPClient, SigningKey: signingKey,
		Issuer: issuer, DiscoveryDocument: aauth.AccessDiscoveryDocument,
		Clock: clock, Admit: config.Admit,
		MaximumDocumentBytes: config.MaximumDocumentBytes,
		Timeout:              config.FetchTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("accessserver: R3: %w", err)
	}
	return &r3Config{
		registry: config.Registry, artifacts: artifacts,
		authorizeDocument: config.AuthorizeDocument, authorizeProposal: config.AuthorizeProposal,
		issuances: config.Issuances,
	}, nil
}

func (server *Server) verifyResourceTokenForAuthorization(
	ctx context.Context,
	compact string,
	clock aauth.Clock,
) (aauth.ResourceTokenClaims, *verifiedR3, error) {
	carriesR3, err := r3dispatch.TokenCarriesClaims(compact)
	if err != nil {
		return aauth.ResourceTokenClaims{}, nil, err
	}
	if !carriesR3 {
		claims, err := aauth.VerifyResourceToken(ctx, compact, server.keyResolver, clock)
		return claims, nil, err
	}
	if server.r3 == nil {
		return aauth.ResourceTokenClaims{}, nil, errors.New("accessserver: R3 resource token is not supported")
	}
	claims, reference, err := r3.VerifyResourceToken(ctx, compact, server.keyResolver, clock)
	if err != nil {
		return aauth.ResourceTokenClaims{}, nil, err
	}
	return claims, &verifiedR3{reference: reference}, nil
}

func (server *Server) fetchR3Artifact(
	ctx context.Context,
	verified *verifiedR3,
	account *string,
) error {
	if verified == nil || server.r3 == nil {
		return errors.New("accessserver: R3 context is incomplete")
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
			return &invalidR3ArtifactError{cause: fmt.Errorf("accessserver: R3 account: %w", err)}
		}
		verified.document = document
		verified.exact = artifact.ExactBytes()
		verified.kind = r3.ArtifactDocument
		verified.vocabulary = document.OperationSet().Vocabulary()
		return nil
	}
	if proposal, ok := artifact.Proposal(); ok {
		if err := r3.ValidateProposalAccount(proposal, account); err != nil {
			return &invalidR3ArtifactError{cause: fmt.Errorf("accessserver: R3 proposal account: %w", err)}
		}
		verified.proposal = proposal
		verified.exact = artifact.ExactBytes()
		verified.kind = r3.ArtifactProposal
		verified.vocabulary = proposal.Operation().Vocabulary()
		return nil
	}
	return &invalidR3ArtifactError{cause: errors.New("accessserver: R3 artifact is unclassified")}
}

func (server *Server) commitR3Issuance(
	ctx context.Context,
	claims aauth.AuthTokenClaims,
	resource aauth.ResourceTokenClaims,
	verified *verifiedR3,
	agent, parentAgent string,
) error {
	if verified == nil || server.r3 == nil {
		return errors.New("accessserver: R3 issuance context is incomplete")
	}
	record := r3.IssuanceRecord{
		AuthTokenReference: aauth.TokenReference{Issuer: claims.Issuer, JTI: claims.JTI},
		Resource:           claims.Audience, R3Reference: verified.reference,
		Vocabulary: verified.vocabulary,
		IssuedAt:   time.Unix(claims.IssuedAt, 0).UTC(), PersonServer: claims.PersonServer,
		Subject: claims.Subject, Account: cloneStringPointer(claims.Account),
		PresentedJTI: resource.PresentedJTI, AgentJKT: resource.AgentJKT,
		Agent: agent, ParentAgent: parentAgent,
	}
	return server.r3.issuances.Commit(ctx, record)
}
