package agentprovider

import (
	"errors"
	"mime"
	"net/http"
	"strings"

	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// EnrollmentHandler returns the hosted profiles' shared enrollment operation. The
// host chooses where to mount it; AAuth Bootstrap does not define a route.
func (service *EnrollmentService) EnrollmentHandler() http.Handler {
	if service == nil {
		return http.NotFoundHandler()
	}
	return http.HandlerFunc(service.serveEnrollment)
}

// RefreshHandler returns the two-key profile's Agent-token refresh operation.
// The host chooses where to mount it; AAuth Bootstrap does not define a route.
func (service *EnrollmentService) RefreshHandler() http.Handler {
	if service == nil {
		return http.NotFoundHandler()
	}
	return http.HandlerFunc(service.serveRefresh)
}

// SingleKeyRefreshHandler returns the single-durable-key refresh operation.
// The host chooses where to mount it; AAuth Bootstrap does not define a route.
func (service *EnrollmentService) SingleKeyRefreshHandler() http.Handler {
	if service == nil {
		return http.NotFoundHandler()
	}
	return http.HandlerFunc(service.serveSingleKeyRefresh)
}

func (service *EnrollmentService) serveEnrollment(response http.ResponseWriter, request *http.Request) {
	if !acceptJSONPost(response, request) {
		return
	}
	prepared, err := signaturekey.PrepareRequest(request, service.provider.clock, signaturekey.VerifyOptions{
		AcceptedSchemes:        []signaturekey.Scheme{signaturekey.SchemeHWK},
		RequiredComponents:     []string{"content-type", "content-digest"},
		RequireExactComponents: true,
		MaxBodyBytes:           httpapi.DefaultMaxBodyBytes,
	})
	if err != nil {
		writeSignatureProblem(response, err)
		return
	}
	key, ok := prepared.Credential().InlineJWK()
	if !ok {
		writeSignatureProblem(response, signaturekey.NewError(signaturekey.ErrorInvalidKey, errors.New("agentprovider: hwk credential is required")))
		return
	}
	proof, err := prepared.Verify(key)
	if err != nil {
		writeSignatureProblem(response, err)
		return
	}
	if err := service.validateProviderAuthority(proof); err != nil {
		writeSignatureProblem(response, err)
		return
	}
	record, err := service.Enroll(request.Context(), proof)
	if err != nil {
		if errors.Is(err, ErrInvalidEnrollmentRequest) {
			httpapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", err)
			return
		}
		if errors.Is(err, ErrEnrollmentDenied) {
			httpapi.WriteProblem(response, http.StatusForbidden, "enrollment_denied", err)
			return
		}
		if errors.Is(err, ErrEnrollmentInactive) {
			httpapi.WriteProblem(response, http.StatusForbidden, "enrollment_inactive", err)
			return
		}
		if errors.Is(err, ErrEnrollmentConflict) {
			httpapi.WriteProblem(response, http.StatusConflict, "enrollment_conflict", err)
			return
		}
		httpapi.WriteProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(response, http.StatusCreated, struct {
		Agent string `json:"agent"`
	}{Agent: record.Agent})
}

func (service *EnrollmentService) serveRefresh(response http.ResponseWriter, request *http.Request) {
	if !acceptJSONPost(response, request) {
		return
	}
	prepared, err := signaturekey.PrepareRequest(request, service.provider.clock, signaturekey.VerifyOptions{
		AcceptedSchemes:        []signaturekey.Scheme{signaturekey.SchemeJKTJWT},
		RequiredComponents:     []string{"content-type", "content-digest"},
		RequireExactComponents: true,
		MaxBodyBytes:           httpapi.DefaultMaxBodyBytes,
	})
	if err != nil {
		writeSignatureProblem(response, err)
		return
	}
	proof, delegation, err := prepared.VerifyJKTJWT()
	if err != nil {
		writeSignatureProblem(response, err)
		return
	}
	if err := service.validateProviderAuthority(proof); err != nil {
		writeSignatureProblem(response, err)
		return
	}
	record, err := service.Refresh(request.Context(), proof, delegation)
	service.writeRefreshResponse(response, record, err)
}

func (service *EnrollmentService) serveSingleKeyRefresh(response http.ResponseWriter, request *http.Request) {
	if !acceptJSONPost(response, request) {
		return
	}
	prepared, err := signaturekey.PrepareRequest(request, service.provider.clock, signaturekey.VerifyOptions{
		AcceptedSchemes:        []signaturekey.Scheme{signaturekey.SchemeHWK},
		RequiredComponents:     []string{"content-type", "content-digest"},
		RequireExactComponents: true,
		MaxBodyBytes:           httpapi.DefaultMaxBodyBytes,
	})
	if err != nil {
		writeSignatureProblem(response, err)
		return
	}
	key, ok := prepared.Credential().InlineJWK()
	if !ok {
		writeSignatureProblem(response, signaturekey.NewError(
			signaturekey.ErrorInvalidKey,
			errors.New("agentprovider: hwk credential is required"),
		))
		return
	}
	proof, err := prepared.Verify(key)
	if err != nil {
		writeSignatureProblem(response, err)
		return
	}
	if err := service.validateProviderAuthority(proof); err != nil {
		writeSignatureProblem(response, err)
		return
	}
	record, err := service.RefreshSingleKey(request.Context(), proof)
	service.writeRefreshResponse(response, record, err)
}

func (service *EnrollmentService) writeRefreshResponse(
	response http.ResponseWriter,
	record RefreshRecord,
	err error,
) {
	if err != nil {
		if errors.Is(err, ErrInvalidRefreshRequest) {
			httpapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", err)
			return
		}
		if errors.Is(err, ErrRefreshDenied) {
			httpapi.WriteProblem(response, http.StatusForbidden, "refresh_denied", err)
			return
		}
		if errors.Is(err, ErrEnrollmentNotFound) {
			httpapi.WriteProblem(response, http.StatusNotFound, "enrollment_not_found", err)
			return
		}
		if errors.Is(err, ErrEnrollmentInactive) {
			httpapi.WriteProblem(response, http.StatusForbidden, "enrollment_inactive", err)
			return
		}
		if errors.Is(err, ErrEnrollmentConflict) {
			httpapi.WriteProblem(response, http.StatusConflict, "enrollment_conflict", err)
			return
		}
		if errors.Is(err, ErrRefreshConflict) {
			httpapi.WriteProblem(response, http.StatusConflict, "refresh_conflict", err)
			return
		}
		if errors.Is(err, ErrRefreshExpired) {
			writeSignatureProblem(response, signaturekey.NewError(signaturekey.ErrorExpiredJWT, err))
			return
		}
		httpapi.WriteProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(response, http.StatusOK, struct {
		AgentToken string `json:"agent_token"`
	}{AgentToken: record.AgentToken})
}

func (service *EnrollmentService) validateProviderAuthority(proof signaturekey.VerifiedRequest) error {
	expected := strings.TrimPrefix(service.provider.issuer, "https://")
	if proof.Authority() != expected {
		return signaturekey.NewError(
			signaturekey.ErrorInvalidRequest,
			errors.New("agentprovider: signed authority does not match the Agent Provider"),
		)
	}
	return nil
}

func acceptJSONPost(response http.ResponseWriter, request *http.Request) bool {
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		httpapi.WriteProblem(response, http.StatusMethodNotAllowed, "invalid_request", errors.New("agentprovider: POST is required"))
		return false
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		httpapi.WriteProblem(response, http.StatusUnsupportedMediaType, "invalid_request", errors.New("agentprovider: application/json is required"))
		return false
	}
	return true
}

func writeSignatureProblem(response http.ResponseWriter, err error) {
	failure := signaturekey.NormalizeError(err, signaturekey.ErrorInvalidSignature)
	httpapi.WriteProblem(response, http.StatusUnauthorized, string(failure.Code), failure)
}
