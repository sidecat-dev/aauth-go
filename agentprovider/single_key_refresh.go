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
	if err := httpapi.DecodeJSON(bytes.NewReader(exactBody), httpapi.DefaultMaxBodyBytes, &input); err != nil {
		return RefreshRecord{}, fmt.Errorf("%w: refresh body: %v", ErrInvalidRefreshRequest, err)
	}
	if input.PersonServer != "" {
		if err := aauth.ValidateServerIdentifier(input.PersonServer); err != nil {
			return RefreshRecord{}, fmt.Errorf("%w: requested Person Server: %v", ErrInvalidRefreshRequest, err)
		}
	}
	requestJTI, requestExpiresAt, err := singleKeyRequestIdentity(proof, input)
	if err != nil {
		return RefreshRecord{}, err
	}

	requestDigest := singleKeyRefreshRequestSHA256(exactBody)
	retained, err := service.store.LoadRefresh(ctx, identity, requestJTI)
	if err == nil {
		if retained.Identity != identity || retained.Profile != RefreshProfileSingleKey ||
			retained.RequestJTI != requestJTI || retained.RequestSHA256 != requestDigest ||
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
		RequestJTI:       requestJTI,
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

// singleKeyRequestIdentity returns the identity and retention bound of one
// single-key refresh. Bootstrap's single-key refresh is the hwk-signed request
// alone and names no request identifier, so a body without refresh_jti and
// refresh_expires_at is identified by its own verified HTTP signature and kept
// until that signature could no longer verify: an exact replay inside the
// signature window returns the retained token. A body that names both chooses
// its identity, so a caller can recover a lost answer with a freshly signed
// request for up to 24 hours. A body that names only one is invalid.
func singleKeyRequestIdentity(proof signaturekey.VerifiedRequest, input refreshHTTPInput) (string, time.Time, error) {
	verifiedAt := proof.VerifiedAt().UTC().Truncate(time.Second)
	if input.RefreshJTI == "" && input.RefreshExpiresAt == 0 {
		requestExpiresAt := proof.Created().Add(proof.MaxAge()).UTC()
		if !requestExpiresAt.After(verifiedAt) {
			return "", time.Time{}, ErrRefreshExpired
		}
		return signatureRefreshJTIPrefix + proof.ReplayKey(), requestExpiresAt, nil
	}
	if strings.TrimSpace(input.RefreshJTI) == "" || input.RefreshJTI != strings.TrimSpace(input.RefreshJTI) {
		return "", time.Time{}, fmt.Errorf("%w: refresh_jti is required without surrounding whitespace when refresh_expires_at is present", ErrInvalidRefreshRequest)
	}
	if strings.HasPrefix(input.RefreshJTI, signatureRefreshJTIPrefix) {
		return "", time.Time{}, fmt.Errorf("%w: refresh_jti must not begin with %q", ErrInvalidRefreshRequest, signatureRefreshJTIPrefix)
	}
	requestExpiresAt := time.Unix(input.RefreshExpiresAt, 0).UTC()
	if !requestExpiresAt.After(verifiedAt) || requestExpiresAt.After(verifiedAt.Add(maximumSingleKeyRefreshWindow)) {
		return "", time.Time{}, fmt.Errorf("%w: refresh_expires_at must be within 24 hours after verification", ErrInvalidRefreshRequest)
	}
	return input.RefreshJTI, requestExpiresAt, nil
}

// signatureRefreshJTIPrefix marks a single-key refresh identity taken from the
// request's own signature rather than a caller-chosen refresh_jti.
const signatureRefreshJTIPrefix = "signature:"

func singleKeyRefreshRequestSHA256(exactBody []byte) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte(RefreshProfileSingleKey))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(exactBody)
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}
