package agentprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const maximumSingleKeyRefreshWindow = 24 * time.Hour

// RefreshSingleKey applies host policy to one verified single-durable-key
// request. SingleKeyRefreshHandler is the normal profile entry point.
func (service *EnrollmentService) RefreshSingleKey(
	ctx context.Context,
	proof signaturekey.VerifiedRequest,
) (RefreshRecord, error) {
	if service == nil || service.provider == nil || service.store == nil || service.refresh == nil {
		return RefreshRecord{}, errors.New("aauth: Agent Provider refresh service is required")
	}
	if ctx == nil {
		return RefreshRecord{}, errors.New("aauth: refresh context is required")
	}
	if err := service.validateProfileProof(proof, signaturekey.SchemeHWK); err != nil {
		return RefreshRecord{}, fmt.Errorf("%w: %v", ErrInvalidRefreshRequest, err)
	}
	identityKey := proof.PublicKey()
	identity, err := identityKey.ThumbprintURI()
	if err != nil {
		return RefreshRecord{}, fmt.Errorf("aauth: single-key refresh identity: %w", err)
	}
	if proof.Signer() != identity {
		return RefreshRecord{}, fmt.Errorf("%w: proof does not match its durable identity", ErrInvalidRefreshRequest)
	}
	var input refreshHTTPInput
	exactBody := proof.ExactBody()
	if err := httpapi.DecodeJSON(bytes.NewReader(exactBody), httpapi.DefaultMaxBodyBytes, &input); err != nil ||
		!json.Valid(input.Evidence) {
		return RefreshRecord{}, fmt.Errorf("%w: evidence is required", ErrInvalidRefreshRequest)
	}
	if input.PersonServer != "" {
		if err := aauth.ValidateServerIdentifier(input.PersonServer); err != nil {
			return RefreshRecord{}, fmt.Errorf("%w: requested Person Server: %v", ErrInvalidRefreshRequest, err)
		}
	}
	if strings.TrimSpace(input.RefreshJTI) == "" || input.RefreshJTI != strings.TrimSpace(input.RefreshJTI) {
		return RefreshRecord{}, fmt.Errorf("%w: refresh_jti is required without surrounding whitespace", ErrInvalidRefreshRequest)
	}
	verifiedAt := proof.VerifiedAt().UTC().Truncate(time.Second)
	requestExpiresAt := time.Unix(input.RefreshExpiresAt, 0).UTC()
	if !requestExpiresAt.After(verifiedAt) || requestExpiresAt.After(verifiedAt.Add(maximumSingleKeyRefreshWindow)) {
		return RefreshRecord{}, fmt.Errorf("%w: refresh_expires_at must be within 24 hours after verification", ErrInvalidRefreshRequest)
	}

	requestDigest := singleKeyRefreshRequestSHA256(exactBody)
	retained, err := service.store.LoadRefresh(ctx, identity, input.RefreshJTI)
	if err == nil {
		if retained.Identity != identity || retained.Profile != RefreshProfileSingleKey ||
			retained.RequestJTI != input.RefreshJTI || retained.RequestSHA256 != requestDigest ||
			retained.PersonServer != input.PersonServer || !retained.Confirmation.Equal(identityKey) ||
			!retained.RequestExpiresAt.Equal(requestExpiresAt) || retained.AgentToken == "" {
			return RefreshRecord{}, ErrRefreshConflict
		}
		return retained, nil
	}
	if !errors.Is(err, ErrRefreshNotFound) {
		return RefreshRecord{}, err
	}
	enrollment, err := service.store.LoadEnrollment(ctx, identity)
	if err != nil {
		return RefreshRecord{}, err
	}
	if enrollment.State != EnrollmentActive {
		return RefreshRecord{}, ErrEnrollmentInactive
	}
	if enrollment.Identity != identity || !enrollment.IdentityKey.Equal(identityKey) {
		return RefreshRecord{}, ErrEnrollmentConflict
	}
	decision, err := service.refresh(ctx, RefreshRequest{
		Enrollment:            enrollment,
		Profile:               RefreshProfileSingleKey,
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
		Agent:            enrollment.Agent,
		PersonServer:     decision.PersonServer,
		PublicKey:        identityKey,
		Lifetime:         decision.Lifetime,
		AdditionalClaims: decision.AdditionalClaims,
	}, issuedAt)
	if err != nil {
		return RefreshRecord{}, err
	}
	candidate := RefreshRecord{
		Identity:         identity,
		Profile:          RefreshProfileSingleKey,
		RequestJTI:       input.RefreshJTI,
		RequestSHA256:    requestDigest,
		Agent:            enrollment.Agent,
		PersonServer:     decision.PersonServer,
		Confirmation:     identityKey,
		RequestExpiresAt: requestExpiresAt,
		AgentToken:       compact,
		TokenExpiresAt:   tokenExpiresAt,
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

func singleKeyRefreshRequestSHA256(exactBody []byte) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte(RefreshProfileSingleKey))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(exactBody)
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}
