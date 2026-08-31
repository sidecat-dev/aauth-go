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

// MCPR3Config enables the immediate direct-grant MCP profile. It does not
// implement r3_per_call.
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
	// Issuances is required and atomically retains the token and audit record.
	Issuances R3IssuanceStore
}

// MCPR3Authorization is the exact verified Resource definition presented to
// the existing host authorization policy.
type MCPR3Authorization struct {
	Reference r3.Reference
	Document  r3.Document
}

type mcpR3Config struct {
	documents *r3fetch.Client
	issuances R3IssuanceStore
}

type verifiedMCPR3 struct {
	reference r3.Reference
	document  r3.Document
	exact     []byte
}

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
	return &mcpR3Config{documents: documents, issuances: config.Issuances}, nil
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

func (server *Server) fetchMCPR3Document(
	ctx context.Context,
	verified *verifiedMCPR3,
	account *string,
) error {
	if verified == nil || server.mcpR3 == nil {
		return errors.New("accessserver: MCP R3 context is incomplete")
	}
	document, exact, err := server.mcpR3.documents.Fetch(ctx, verified.reference)
	if err != nil {
		if r3fetch.IsDocumentError(err) {
			return &invalidMCPR3DocumentError{cause: err}
		}
		return err
	}
	if err := r3.ValidateDocumentAccount(document, account); err != nil {
		return &invalidMCPR3DocumentError{cause: fmt.Errorf("accessserver: MCP R3 account: %w", err)}
	}
	verified.document = document
	verified.exact = exact
	return nil
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
		AgentJKT: resource.AgentJKT, Agent: agent, ParentAgent: parentAgent,
	}
	return server.mcpR3.issuances.Commit(ctx, record)
}
