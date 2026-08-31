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

// MCPR3Config enables the immediate direct-grant MCP consent profile on a
// federated Person Server. It does not implement r3_per_call.
type MCPR3Config struct {
	// Admit is required and approves the exact document URI before transport.
	// Fetches reuse the federated server's configured HTTP client; its clone
	// disables cookies and refuses redirects.
	Admit signaturekey.EgressAdmitter
	// Consent is required and receives verified Core context plus the exact
	// typed R3 reference and document.
	Consent func(context.Context, AuthorizationRequest, r3.Reference, r3.Document) error
	// MaximumDocumentBytes defaults to 1 MiB when zero.
	MaximumDocumentBytes int64
	// FetchTimeout defaults to 10 seconds when zero.
	FetchTimeout time.Duration
}

type mcpR3Config struct {
	documents *r3fetch.Client
	consent   func(context.Context, AuthorizationRequest, r3.Reference, r3.Document) error
}

type verifiedMCPR3 struct {
	reference r3.Reference
	document  r3.Document
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
	return &mcpR3Config{documents: documents, consent: config.Consent}, nil
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

func (server *Server) fetchMCPR3Document(
	ctx context.Context,
	verified *verifiedMCPR3,
	account *string,
) error {
	if verified == nil || server.mcpR3 == nil {
		return errors.New("personserver: MCP R3 context is incomplete")
	}
	document, _, err := server.mcpR3.documents.Fetch(ctx, verified.reference)
	if err != nil {
		if r3fetch.IsDocumentError(err) {
			return &invalidMCPR3DocumentError{cause: err}
		}
		return err
	}
	if err := r3.ValidateDocumentAccount(document, account); err != nil {
		return &invalidMCPR3DocumentError{cause: fmt.Errorf("personserver: MCP R3 account: %w", err)}
	}
	verified.document = document
	return nil
}

func (server *Server) verifyMCPR3AccessResult(
	ctx context.Context,
	compact string,
	verified *verifiedMCPR3,
) (aauth.AuthTokenClaims, error) {
	if verified == nil {
		return aauth.AuthTokenClaims{}, errors.New("personserver: MCP R3 context is required")
	}
	claims, reference, granted, err := r3.VerifyMCPDirectAuthToken(
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
	if _, err := r3.NewGrant(granted, verified.document); err != nil {
		return aauth.AuthTokenClaims{}, fmt.Errorf("personserver: Access Server MCP R3 grant: %w", err)
	}
	return claims, nil
}

func cloneAuthorizationAccount(account *string) *string {
	if account == nil {
		return nil
	}
	cloned := *account
	return &cloned
}
