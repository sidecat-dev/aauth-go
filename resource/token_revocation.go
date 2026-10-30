package resource

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/revocation"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// ErrPersonTokenRevoked reports a person token revoked by the Person Server
// that issued it. A request presenting it is refused with revoked_jwt, and no
// resource token naming it is issued.
var ErrPersonTokenRevoked = errors.New("resource: person token revoked")

// PersonTokenRevocationStore retains person-token references revoked by the
// Person Server that issued them. It has the contract of
// AgentTokenRevocationStore: Revoke is idempotent, IsRevoked and Revoke for
// one reference are linearizable, and a marker is retained at least through
// the request's ExpiresAt plus the Resource's clock skew. Revoke may return
// aauth.ErrRevocationLimitReached when the issuer already holds as many
// entries as the store allows.
type PersonTokenRevocationStore interface {
	Revoke(context.Context, aauth.RevocationRequest) error
	IsRevoked(context.Context, aauth.TokenReference) (bool, error)
}

// RevocationConfig adds person-token revocation and the Resource's own
// resource-token revocations to a Resource.
type RevocationConfig struct {
	// PersonTokens records the person tokens Person Servers revoke at this
	// Resource's revocation endpoint. A request presenting a revoked one is
	// refused.
	PersonTokens PersonTokenRevocationStore
	// HTTPClient and Admit carry RevokeResourceToken to the Person Server or
	// Access Server a resource token names. Leave both nil when the Resource
	// does not withdraw resource tokens. The Resource uses a copy of
	// HTTPClient that follows no redirects and sends no cookies.
	HTTPClient *http.Client
	Admit      signaturekey.EgressAdmitter
	// Limits bounds what one caller may send the revocation endpoint. Zero
	// members select defaults.
	Limits aauth.RevocationLimits
}

func (server *Server) configureRevocation(config *RevocationConfig) error {
	limits := aauth.RevocationLimits{}
	if config != nil {
		limits = config.Limits
	}
	if err := revocation.ValidateLimits(limits); err != nil {
		return fmt.Errorf("aauth: resource: %w", err)
	}
	server.revocationLimits = revocation.Limits(limits)
	server.revocationLimiter = revocation.NewLimiter(limits)
	if config == nil {
		return nil
	}
	server.personTokenRevocations = config.PersonTokens
	if config.HTTPClient == nil && config.Admit == nil {
		return nil
	}
	if server.signingKey.ID() == "" {
		return errors.New("aauth: resource-token revocation requires a Resource that issues resource tokens")
	}
	sender, err := revocation.NewSender(config.HTTPClient, config.Admit, server.signingKey, server.issuer, aauth.ResourceDiscoveryDocument, server.clock)
	if err != nil {
		return fmt.Errorf("aauth: resource: %w", err)
	}
	server.resourceTokenSender = sender
	server.resourceTokenCascades = revocation.NewTracker()
	return nil
}

// checkPersonTokenRevoked refuses a verified person token its Person Server
// revoked. It runs after the request proof verified, so only the token's
// holder learns of the revocation.
func (server *Server) checkPersonTokenRevoked(ctx context.Context, claims aauth.PersonTokenClaims) error {
	if server.personTokenRevocations == nil {
		return nil
	}
	revoked, err := server.personTokenRevocations.IsRevoked(ctx, aauth.TokenReference{Issuer: claims.Issuer, JTI: claims.JTI})
	if err != nil {
		return &revocationStoreError{cause: fmt.Errorf("check person-token revocation: %w", err)}
	}
	if revoked {
		return &requestTokenError{cause: ErrPersonTokenRevoked}
	}
	return nil
}

// ResourceTokenRevocation names one resource token this Resource issued and
// now withdraws.
type ResourceTokenRevocation struct {
	JTI string
	// ExpiresAt is the resource token's exp.
	ExpiresAt time.Time
	// Audience is the token's aud: the Person Server in three-party access,
	// the Access Server in four-party.
	Audience string
	// PersonServer is the token's ps. In four-party access it is revoked at
	// as well.
	PersonServer string
}

// ResourceTokenRevocationResult reports one attempt for each recipient.
type ResourceTokenRevocationResult struct {
	Attempts []aauth.RevocationAttempt
}

// RevokeResourceToken withdraws a resource token this Resource issued. It
// revokes it at the party named in the token's aud and, in four-party access,
// at its ps as well. Each recipient then refuses a token request naming it
// with revoked_resource_token, and ends a request waiting on it with revoked.
//
// Each call makes one attempt at each recipient that has not recorded the
// revocation. Repeating the call is safe and re-attempts the failures.
func (server *Server) RevokeResourceToken(ctx context.Context, withdrawn ResourceTokenRevocation) (ResourceTokenRevocationResult, error) {
	if server == nil || server.resourceTokenSender == nil {
		return ResourceTokenRevocationResult{}, errors.New("aauth: resource-token revocation is not configured")
	}
	if ctx == nil {
		return ResourceTokenRevocationResult{}, errors.New("aauth: revocation context is required")
	}
	reference := aauth.TokenReference{Issuer: server.issuer, JTI: withdrawn.JTI}
	if err := aauth.ValidateRevocationRequest(aauth.RevocationRequest{Reference: reference, ExpiresAt: withdrawn.ExpiresAt}); err != nil {
		return ResourceTokenRevocationResult{}, err
	}
	if err := aauth.ValidateServerIdentifier(withdrawn.Audience); err != nil {
		return ResourceTokenRevocationResult{}, fmt.Errorf("aauth: resource-token audience: %w", err)
	}
	var targets []revocation.Target
	switch server.authorizationTopology {
	case authorizationTopologyPersonServer:
		if withdrawn.PersonServer != "" && withdrawn.PersonServer != withdrawn.Audience {
			return ResourceTokenRevocationResult{}, errors.New("aauth: a three-party resource token's aud is its ps")
		}
		targets = append(targets, revocation.Target{
			Recipient: withdrawn.Audience, Metadata: aauth.PersonDiscoveryDocument,
			JTI: withdrawn.JTI, ExpiresAt: withdrawn.ExpiresAt,
		})
	case authorizationTopologyFederated:
		if withdrawn.Audience != server.accessServer {
			return ResourceTokenRevocationResult{}, errors.New("aauth: a four-party resource token's aud is the Access Server")
		}
		if err := aauth.ValidateServerIdentifier(withdrawn.PersonServer); err != nil {
			return ResourceTokenRevocationResult{}, fmt.Errorf("aauth: four-party resource-token ps: %w", err)
		}
		targets = append(targets,
			revocation.Target{Recipient: withdrawn.Audience, Metadata: aauth.AccessDiscoveryDocument, JTI: withdrawn.JTI, ExpiresAt: withdrawn.ExpiresAt},
			revocation.Target{Recipient: withdrawn.PersonServer, Metadata: aauth.PersonDiscoveryDocument, JTI: withdrawn.JTI, ExpiresAt: withdrawn.ExpiresAt},
		)
	default:
		return ResourceTokenRevocationResult{}, errors.New("aauth: this Resource issues no resource tokens")
	}
	result := server.resourceTokenCascades.Step(ctx, server.resourceTokenSender, revocation.Run{
		Key: reference, Caller: server.issuer, Targets: targets, Retry: true, Hold: revocation.DefaultHold,
		RetainUntil: withdrawn.ExpiresAt.Add(revocation.Skew), Now: server.clock.Now().UTC(),
	})
	return ResourceTokenRevocationResult{Attempts: revocation.Aggregate(result)}, nil
}
