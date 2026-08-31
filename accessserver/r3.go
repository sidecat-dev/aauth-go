package accessserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	aauth "aauth-go"
	"aauth-go/internal/r3dispatch"
	"aauth-go/internal/r3fetch"
	"aauth-go/jose"
	"aauth-go/r3"
	"aauth-go/signaturekey"
)

// MCPR3Config enables MCP class-document and per-call proposal authorization.
// Each artifact is fetched once, classified from its exact contents, and sent
// only to the policy callback for that artifact kind.
type MCPR3Config struct {
	// HTTPClient is required. The fetcher clones it, disables cookies, refuses
	// redirects, and leaves the caller's client unchanged.
	HTTPClient *http.Client
	// Admit is required and approves the exact document URI before transport.
	Admit signaturekey.EgressAdmitter
	// FetchTimeout defaults to 10 seconds when zero.
	FetchTimeout time.Duration
	// MaximumDocumentBytes defaults to 1 MiB when zero.
	MaximumDocumentBytes int64
	// AuthorizeProposal receives verified Core context plus one exact per-call
	// proposal. A proposal is refused when this callback is nil; class-document
	// authorization continues to use Config.Authorize.
	AuthorizeProposal func(
		context.Context,
		AuthorizationRequest,
		r3.Reference,
		r3.MCPProposal,
	) (MCPR3ProposalDecision, error)
	// Issuances is required and atomically retains the token and audit record.
	Issuances R3IssuanceStore
}

// MCPR3Authorization is the exact verified class document presented to the
// existing host authorization policy.
type MCPR3Authorization struct {
	Reference r3.Reference
	Document  r3.Document
}

// MCPR3ProposalDecision is the Core scope and lifetime decision for one exact
// per-call proposal. The proposal itself determines the sole R3 operation;
// policy cannot substitute another operation or carry r3_per_call forward.
type MCPR3ProposalDecision struct {
	Scopes   []string
	Lifetime time.Duration
}

type mcpR3Config struct {
	documents         *r3fetch.Client
	authorizeProposal func(
		context.Context,
		AuthorizationRequest,
		r3.Reference,
		r3.MCPProposal,
	) (MCPR3ProposalDecision, error)
	issuances R3IssuanceStore
}

type verifiedMCPR3 struct {
	reference r3.Reference
	document  r3.Document
	proposal  r3.MCPProposal
	exact     []byte
	kind      mcpR3ArtifactKind
}

type mcpR3ArtifactKind uint8

const (
	mcpR3ArtifactInvalid mcpR3ArtifactKind = iota
	mcpR3ArtifactDocument
	mcpR3ArtifactProposal
)

type invalidMCPR3DocumentError struct{ cause error }

func (failure *invalidMCPR3DocumentError) Error() string { return failure.cause.Error() }
func (failure *invalidMCPR3DocumentError) Unwrap() error { return failure.cause }

func isInvalidMCPR3Document(err error) bool {
	var failure *invalidMCPR3DocumentError
	return errors.As(err, &failure)
}

func newMCPR3Config(
	config *MCPR3Config,
	signingKey jose.SigningKey,
	issuer string,
	clock aauth.Clock,
) (*mcpR3Config, error) {
	if config == nil {
		return nil, nil
	}
	if config.Issuances == nil {
		return nil, errors.New("accessserver: MCP R3 issuance store is required")
	}
	documents, err := r3fetch.New(r3fetch.Config{
		HTTPClient: config.HTTPClient, SigningKey: signingKey,
		Issuer: issuer, DiscoveryDocument: aauth.AccessDiscoveryDocument,
		Clock: clock, Admit: config.Admit,
		MaximumDocumentBytes: config.MaximumDocumentBytes,
		Timeout:              config.FetchTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("accessserver: MCP R3: %w", err)
	}
	return &mcpR3Config{
		documents: documents, authorizeProposal: config.AuthorizeProposal,
		issuances: config.Issuances,
	}, nil
}

func (server *Server) verifyResourceTokenForAuthorization(
	ctx context.Context,
	compact string,
	clock aauth.Clock,
) (aauth.ResourceTokenClaims, *verifiedMCPR3, error) {
	carriesR3, err := r3dispatch.TokenCarriesClaims(compact)
	if err != nil {
		return aauth.ResourceTokenClaims{}, nil, err
	}
	if !carriesR3 {
		claims, err := aauth.VerifyResourceToken(ctx, compact, server.keyResolver, clock)
		return claims, nil, err
	}
	if server.mcpR3 == nil {
		return aauth.ResourceTokenClaims{}, nil, errors.New("accessserver: MCP R3 resource token is not supported")
	}
	claims, reference, err := r3.VerifyMCPResourceToken(ctx, compact, server.keyResolver, clock)
	if err != nil {
		return aauth.ResourceTokenClaims{}, nil, err
	}
	return claims, &verifiedMCPR3{reference: reference}, nil
}

func (server *Server) fetchMCPR3Artifact(
	ctx context.Context,
	verified *verifiedMCPR3,
	account *string,
) error {
	if verified == nil || server.mcpR3 == nil {
		return errors.New("accessserver: MCP R3 context is incomplete")
	}
	artifact, err := server.mcpR3.documents.FetchArtifact(ctx, verified.reference)
	if err != nil {
		if r3fetch.IsDocumentError(err) {
			return &invalidMCPR3DocumentError{cause: err}
		}
		return err
	}
	if document, ok := artifact.Document(); ok {
		if err := r3.ValidateDocumentAccount(document, account); err != nil {
			return &invalidMCPR3DocumentError{cause: fmt.Errorf("accessserver: MCP R3 account: %w", err)}
		}
		verified.document = document
		verified.exact = artifact.ExactBytes()
		verified.kind = mcpR3ArtifactDocument
		return nil
	}
	if proposal, ok := artifact.Proposal(); ok {
		if err := r3.ValidateProposalAccount(proposal, account); err != nil {
			return &invalidMCPR3DocumentError{cause: fmt.Errorf("accessserver: MCP R3 proposal account: %w", err)}
		}
		verified.proposal = proposal
		verified.exact = artifact.ExactBytes()
		verified.kind = mcpR3ArtifactProposal
		return nil
	}
	return &invalidMCPR3DocumentError{cause: errors.New("accessserver: MCP R3 artifact is unclassified")}
}

func (server *Server) commitMCPR3Issuance(
	ctx context.Context,
	compact string,
	claims aauth.AuthTokenClaims,
	resource aauth.ResourceTokenClaims,
	verified *verifiedMCPR3,
	agent, parentAgent string,
) error {
	if verified == nil || server.mcpR3 == nil {
		return errors.New("accessserver: MCP R3 issuance context is incomplete")
	}
	record := R3IssuanceRecord{
		AuthTokenReference: aauth.TokenReference{Issuer: claims.Issuer, JTI: claims.JTI},
		ExactAuthToken:     compact, Resource: claims.Audience, R3Reference: verified.reference,
		IssuedAt: time.Unix(claims.IssuedAt, 0).UTC(), PersonServer: claims.PersonServer,
		Subject: claims.Subject, Account: cloneStringPointer(claims.Account),
		PresentedJTI: resource.PresentedJTI, AgentJKT: resource.AgentJKT,
		Agent: agent, ParentAgent: parentAgent,
	}
	return server.mcpR3.issuances.Commit(ctx, record)
}
