package personserver

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

// MCPR3Config enables immediate class and per-call MCP consent on a federated
// Person Server. Each artifact is independently fetched and sent only to its
// corresponding policy callback.
type MCPR3Config struct {
	// Admit is required and approves the exact document URI before transport.
	// Fetches reuse the federated server's configured HTTP client; its clone
	// disables cookies and refuses redirects.
	Admit signaturekey.EgressAdmitter
	// Consent is required and receives verified Core context plus the exact
	// typed R3 reference and document.
	Consent func(context.Context, AuthorizationRequest, r3.Reference, r3.Document) error
	// ConsentProposal receives verified Core context plus one exact per-call
	// proposal. A proposal is refused when this callback is nil; class-document
	// consent continues to use Consent.
	ConsentProposal func(context.Context, AuthorizationRequest, r3.Reference, r3.MCPProposal) error
	// MaximumDocumentBytes defaults to 1 MiB when zero.
	MaximumDocumentBytes int64
	// FetchTimeout defaults to 10 seconds when zero.
	FetchTimeout time.Duration
}

type mcpR3Config struct {
	documents       *r3fetch.Client
	consent         func(context.Context, AuthorizationRequest, r3.Reference, r3.Document) error
	consentProposal func(context.Context, AuthorizationRequest, r3.Reference, r3.MCPProposal) error
}

type verifiedMCPR3 struct {
	reference     r3.Reference
	document      r3.Document
	proposal      r3.MCPProposal
	exactProposal []byte
	kind          mcpR3ArtifactKind
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
	httpClient *http.Client,
	signingKey jose.SigningKey,
	issuer string,
	clock aauth.Clock,
) (*mcpR3Config, error) {
	if config == nil {
		return nil, nil
	}
	if config.Consent == nil {
		return nil, errors.New("personserver: MCP R3 consent policy is required")
	}
	documents, err := r3fetch.New(r3fetch.Config{
		HTTPClient: httpClient, SigningKey: signingKey,
		Issuer: issuer, DiscoveryDocument: aauth.PersonDiscoveryDocument,
		Clock: clock, Admit: config.Admit,
		MaximumDocumentBytes: config.MaximumDocumentBytes,
		Timeout:              config.FetchTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("personserver: MCP R3: %w", err)
	}
	return &mcpR3Config{
		documents: documents, consent: config.Consent,
		consentProposal: config.ConsentProposal,
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
		return aauth.ResourceTokenClaims{}, nil, errors.New("personserver: MCP R3 resource token is not supported")
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
		return errors.New("personserver: MCP R3 context is incomplete")
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
			return &invalidMCPR3DocumentError{cause: fmt.Errorf("personserver: MCP R3 account: %w", err)}
		}
		verified.document = document
		verified.kind = mcpR3ArtifactDocument
		return nil
	}
	if proposal, ok := artifact.Proposal(); ok {
		if err := r3.ValidateProposalAccount(proposal, account); err != nil {
			return &invalidMCPR3DocumentError{cause: fmt.Errorf("personserver: MCP R3 proposal account: %w", err)}
		}
		verified.proposal = proposal
		verified.exactProposal = artifact.ExactBytes()
		verified.kind = mcpR3ArtifactProposal
		return nil
	}
	return &invalidMCPR3DocumentError{cause: errors.New("personserver: MCP R3 artifact is unclassified")}
}

func (server *Server) verifyMCPR3AccessResult(
	ctx context.Context,
	compact string,
	verified *verifiedMCPR3,
) (aauth.AuthTokenClaims, error) {
	if verified == nil {
		return aauth.AuthTokenClaims{}, errors.New("personserver: MCP R3 context is required")
	}
	switch verified.kind {
	case mcpR3ArtifactDocument:
		claims, reference, operations, err := r3.VerifyMCPAuthTokenClaims(
			ctx, compact, server.keyResolver, server.clock,
		)
		if err != nil {
			return aauth.AuthTokenClaims{}, err
		}
		if reference != verified.reference {
			return aauth.AuthTokenClaims{}, errors.New("personserver: Access Server changed the MCP R3 document reference")
		}
		if err := r3.ValidateDocumentAccount(verified.document, claims.Account); err != nil {
			return aauth.AuthTokenClaims{}, fmt.Errorf("personserver: Access Server MCP R3 account: %w", err)
		}
		if _, err := r3.NewAuthorization(
			operations.GrantedOperations(), operations.PerCallOperations(), verified.document,
		); err != nil {
			return aauth.AuthTokenClaims{}, fmt.Errorf("personserver: Access Server MCP R3 authorization: %w", err)
		}
		return claims, nil
	case mcpR3ArtifactProposal:
		claims, _, _, err := r3.VerifyMCPPerCallAuthToken(
			ctx, compact, server.keyResolver, server.clock,
			verified.reference, verified.exactProposal,
		)
		if err != nil {
			return aauth.AuthTokenClaims{}, fmt.Errorf("personserver: Access Server MCP R3 proposal result: %w", err)
		}
		return claims, nil
	default:
		return aauth.AuthTokenClaims{}, errors.New("personserver: MCP R3 artifact is unclassified")
	}
}

func (server *Server) consentMCPR3(
	ctx context.Context,
	request AuthorizationRequest,
	verified *verifiedMCPR3,
) error {
	if server == nil || server.mcpR3 == nil || verified == nil {
		return errors.New("personserver: MCP R3 consent context is incomplete")
	}
	switch verified.kind {
	case mcpR3ArtifactDocument:
		if server.mcpR3.consent == nil {
			return errors.New("personserver: MCP R3 class consent policy is required")
		}
		return server.mcpR3.consent(ctx, request, verified.reference, verified.document)
	case mcpR3ArtifactProposal:
		if server.mcpR3.consentProposal == nil {
			return errors.New("personserver: MCP R3 proposal consent policy is required")
		}
		return server.mcpR3.consentProposal(ctx, request, verified.reference, verified.proposal)
	default:
		return errors.New("personserver: MCP R3 artifact is unclassified")
	}
}

func cloneAuthorizationAccount(account *string) *string {
	if account == nil {
		return nil
	}
	cloned := *account
	return &cloned
}
