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

type r3Config struct {
	registry        r3.Registry
	artifacts       *r3fetch.Client
	consentDocument func(context.Context, AuthorizationRequest, r3.Reference, r3.Document) error
	consentProposal func(context.Context, AuthorizationRequest, r3.Reference, r3.Proposal) error
}

type verifiedR3 struct {
	reference     r3.Reference
	document      r3.Document
	proposal      r3.Proposal
	exactProposal []byte
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
		return aauth.ResourceTokenClaims{}, nil, errors.New("personserver: R3 resource token is not supported")
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
		verified.kind = r3.ArtifactDocument
		return nil
	}
	if proposal, ok := artifact.Proposal(); ok {
		if err := r3.ValidateProposalAccount(proposal, account); err != nil {
			return &invalidR3ArtifactError{cause: fmt.Errorf("personserver: R3 proposal account: %w", err)}
		}
		verified.proposal = proposal
		verified.exactProposal = artifact.ExactBytes()
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
			verified.reference, verified.exactProposal,
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
