package agentprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// Refresh applies host policy to one verified two-key request.
// RefreshHandler is the normal profile entry point; direct callers must
// prepare the same exact POST proof and separately validate application/json.
func (service *EnrollmentService) Refresh(
	ctx context.Context,
	proof signaturekey.VerifiedRequest,
	delegation signaturekey.JKTJWTDelegation,
) (RefreshRecord, error) {
	if service == nil || service.provider == nil || service.store == nil || service.refresh == nil {
		return RefreshRecord{}, errors.New("aauth: Agent Provider refresh service is required")
	}
	if ctx == nil {
		return RefreshRecord{}, errors.New("aauth: refresh context is required")
	}
	if err := service.validateProfileProof(proof, signaturekey.SchemeJKTJWT); err != nil {
		return RefreshRecord{}, fmt.Errorf("%w: %v", ErrInvalidRefreshRequest, err)
	}
	issuer := delegation.Issuer()
	jti := delegation.JTI()
	identityKey := delegation.IdentityKey()
	confirmationKey := delegation.ConfirmationKey()
	if jti == "" {
		return RefreshRecord{}, fmt.Errorf("%w: verified jkt-jwt proof with jti is required", ErrInvalidRefreshRequest)
	}
	if proof.Signer() != issuer || !proof.PublicKey().Equal(confirmationKey) {
		return RefreshRecord{}, fmt.Errorf("%w: proof does not match its delegation", ErrInvalidRefreshRequest)
	}
	if identityKey.Equal(confirmationKey) {
		return RefreshRecord{}, fmt.Errorf("%w: delegated key must differ from the durable key", ErrInvalidRefreshRequest)
	}
	var input refreshHTTPInput
	exactBody := proof.ExactBody()
	if err := httpapi.DecodeJSON(bytes.NewReader(exactBody), httpapi.DefaultMaxBodyBytes, &input); err != nil {
		return RefreshRecord{}, fmt.Errorf("%w: refresh body: %v", ErrInvalidRefreshRequest, err)
	}
	if input.PersonServer != "" {
		if err := aauth.ValidateServerIdentifier(input.PersonServer); err != nil {
			return RefreshRecord{}, fmt.Errorf("%w: requested Person Server: %v", ErrInvalidRefreshRequest, err)
		}
	}
	if input.RefreshJTI != "" || input.RefreshExpiresAt != 0 {
		return RefreshRecord{}, fmt.Errorf("%w: two-key refresh must not contain single-key identity fields", ErrInvalidRefreshRequest)
	}
	requestDigest := refreshRequestSHA256(delegation, exactBody)
	retained, err := service.store.LoadRefresh(ctx, issuer, jti)
	if err == nil {
		if retained.Identity != issuer || retained.Profile != RefreshProfileTwoKey || retained.RequestJTI != jti ||
			retained.RequestSHA256 != requestDigest || retained.PersonServer != input.PersonServer ||
			!retained.Confirmation.Equal(confirmationKey) || retained.AgentToken == "" {
			return RefreshRecord{}, ErrRefreshConflict
		}
		return retained, nil
	}
	if !errors.Is(err, ErrRefreshNotFound) {
		return RefreshRecord{}, err
	}
	enrollment, err := service.store.LoadEnrollment(ctx, issuer)
	if err != nil {
		return RefreshRecord{}, err
	}
	if enrollment.State != EnrollmentActive {
		return RefreshRecord{}, ErrEnrollmentInactive
	}
	if enrollment.Identity != issuer || !enrollment.IdentityKey.Equal(identityKey) {
		return RefreshRecord{}, ErrEnrollmentConflict
	}
	decision, err := service.refresh(ctx, RefreshRequest{
		Enrollment: enrollment, Profile: RefreshProfileTwoKey, Delegation: delegation,
		RequestedPersonServer: input.PersonServer,
		Evidence:              append(json.RawMessage(nil), input.Evidence...),
	})
	if err != nil {
		return RefreshRecord{}, err
	}
	if decision.PersonServer != input.PersonServer {
		return RefreshRecord{}, errors.New("aauth: refresh policy changed the requested Person Server")
	}
	issuedAt := service.provider.clock.Now().UTC().Truncate(time.Second)
	compact, tokenExpiresAt, err := service.provider.issueAt(ctx, aauth.AgentTokenRequest{
		Agent: enrollment.Agent, PersonServer: decision.PersonServer,
		PublicKey: confirmationKey, Lifetime: decision.Lifetime,
		AdditionalClaims: decision.AdditionalClaims,
	}, issuedAt)
	if err != nil {
		return RefreshRecord{}, err
	}
	candidate := RefreshRecord{
		Identity: issuer, Profile: RefreshProfileTwoKey, RequestJTI: jti,
		RequestSHA256: requestDigest,
		Agent:         enrollment.Agent, PersonServer: decision.PersonServer,
		Confirmation: confirmationKey, RequestExpiresAt: delegation.ExpiresAt(),
		AgentToken:     compact,
		TokenExpiresAt: tokenExpiresAt,
	}
	retained, err = service.store.CommitRefresh(ctx, enrollment, candidate)
	if err != nil {
		return RefreshRecord{}, err
	}
	if !retained.SameRequest(candidate) || retained.AgentToken == "" {
		return RefreshRecord{}, ErrRefreshConflict
	}
	return retained, nil
}

func refreshRequestSHA256(
	delegation signaturekey.JKTJWTDelegation,
	exactBody []byte,
) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte(delegation.Compact()))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(exactBody)
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}
