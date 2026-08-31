package agentprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// Enroll applies host policy to one verified request. EnrollmentHandler is
// the normal profile entry point; direct callers must prepare the same exact
// POST proof and provide separately validated application/json input.
func (service *EnrollmentService) Enroll(
	ctx context.Context,
	proof signaturekey.VerifiedRequest,
) (EnrollmentRecord, error) {
	if service == nil || service.provider == nil || service.store == nil || service.enroll == nil {
		return EnrollmentRecord{}, errors.New("aauth: Agent Provider enrollment service is required")
	}
	if ctx == nil {
		return EnrollmentRecord{}, errors.New("aauth: enrollment context is required")
	}
	if err := service.validateProfileProof(proof, signaturekey.SchemeHWK); err != nil {
		return EnrollmentRecord{}, fmt.Errorf("%w: %v", ErrInvalidEnrollmentRequest, err)
	}
	var input enrollmentHTTPInput
	if err := httpapi.DecodeJSON(bytes.NewReader(proof.ExactBody()), httpapi.DefaultMaxBodyBytes, &input); err != nil || !json.Valid(input.Evidence) {
		return EnrollmentRecord{}, fmt.Errorf("%w: evidence is required", ErrInvalidEnrollmentRequest)
	}
	identityKey := proof.PublicKey()
	identity, err := identityKey.ThumbprintURI()
	if err != nil {
		return EnrollmentRecord{}, fmt.Errorf("aauth: enrollment identity key: %w", err)
	}
	if proof.Signer() != identity {
		return EnrollmentRecord{}, errors.New("aauth: enrollment signer does not match its identity key")
	}
	retained, err := service.store.LoadEnrollment(ctx, identity)
	if err == nil {
		if retained.Identity != identity || retained.Revision == 0 || !retained.IdentityKey.Equal(identityKey) {
			return EnrollmentRecord{}, ErrEnrollmentConflict
		}
		if retained.State != EnrollmentActive {
			return EnrollmentRecord{}, ErrEnrollmentInactive
		}
		if err := aauth.ValidateAgentRelationship(retained.Agent, ""); err != nil {
			return EnrollmentRecord{}, ErrEnrollmentConflict
		}
		if err := aauth.ValidateAgentIssuer(retained.Agent, service.provider.issuer); err != nil {
			return EnrollmentRecord{}, ErrEnrollmentConflict
		}
		return retained, nil
	}
	if !errors.Is(err, ErrEnrollmentNotFound) {
		return EnrollmentRecord{}, err
	}
	decision, err := service.enroll(ctx, EnrollmentRequest{
		Identity: identity, IdentityKey: identityKey,
		Evidence: append(json.RawMessage(nil), input.Evidence...),
	})
	if err != nil {
		return EnrollmentRecord{}, err
	}
	if err := aauth.ValidateAgentIdentifier(decision.Agent); err != nil {
		return EnrollmentRecord{}, fmt.Errorf("aauth: enrollment Agent: %w", err)
	}
	if err := aauth.ValidateAgentRelationship(decision.Agent, ""); err != nil {
		return EnrollmentRecord{}, fmt.Errorf("aauth: enrollment Agent: %w", err)
	}
	if err := aauth.ValidateAgentIssuer(decision.Agent, service.provider.issuer); err != nil {
		return EnrollmentRecord{}, fmt.Errorf("aauth: enrollment Agent: %w", err)
	}
	candidate := EnrollmentRecord{
		Identity: identity, IdentityKey: identityKey,
		Agent: decision.Agent, State: EnrollmentActive, Revision: 1,
	}
	retained, err = service.store.CommitEnrollment(ctx, candidate)
	if err != nil {
		return EnrollmentRecord{}, err
	}
	if !retained.Equal(candidate) {
		return EnrollmentRecord{}, ErrEnrollmentConflict
	}
	return retained, nil
}

func (service *EnrollmentService) validateProfileProof(
	proof signaturekey.VerifiedRequest,
	scheme signaturekey.Scheme,
) error {
	if proof.Scheme() != scheme {
		return fmt.Errorf("verified %s proof is required", scheme)
	}
	if proof.Method() != http.MethodPost {
		return errors.New("verified POST proof is required")
	}
	expectedAuthority := strings.TrimPrefix(service.provider.issuer, "https://")
	if proof.Authority() != expectedAuthority {
		return errors.New("signed authority does not match the Agent Provider")
	}
	if !hasExactEnrollmentProfileComponents(proof.CoveredComponents()) {
		return errors.New("proof does not use the exact enrollment component profile")
	}
	return nil
}

func hasExactEnrollmentProfileComponents(components []string) bool {
	if len(components) != 6 {
		return false
	}
	want := map[string]bool{
		"@method": false, "@authority": false, "@path": false,
		"content-type": false, "content-digest": false, "signature-key": false,
	}
	for _, component := range components {
		seen, expected := want[component]
		if !expected || seen {
			return false
		}
		want[component] = true
	}
	return true
}
