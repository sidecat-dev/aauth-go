package resource

import (
	"crypto/sha256"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/events"
	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// PublicSubscriptionHandler returns the public registration endpoint handler.
func (service *EventService) PublicSubscriptionHandler() http.Handler {
	if service == nil || service.registrationHandler == nil {
		return http.NotFoundHandler()
	}
	return service.registrationHandler
}

func (service *EventService) handlePublicSubscription(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		httpapi.WriteProblem(response, http.StatusMethodNotAllowed, "invalid_request", errors.New("resource: event registration requires POST"))
		return
	}
	if !requestTargetsEndpoint(request, service.subscriptionEndpoint) {
		httpapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", errors.New("resource: event registration target is invalid"))
		return
	}
	if request.Header.Get("Content-Type") != "" {
		if _, _, err := mime.ParseMediaType(request.Header.Get("Content-Type")); err != nil {
			httpapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", errors.New("resource: event registration content type is invalid"))
			return
		}
	}
	verified, ok := service.verifySubscribeRegistration(response, request)
	if !ok {
		return
	}
	compact, claims, proof := verified.compact, verified.claims, verified.proof
	decision, err := service.registerPublic(request.Context(), PublicSubscriptionRequest{
		Token: claims, Parameters: proof.ExactBody(), ContentType: request.Header.Get("Content-Type"),
		VerifiedAt: proof.VerifiedAt(),
	})
	if err != nil {
		if errors.Is(err, ErrEventSubscriptionDenied) {
			httpapi.WriteProblem(response, http.StatusForbidden, "event_subscription_denied", err)
		} else {
			httpapi.WriteProblem(response, http.StatusInternalServerError, "server_error", err)
		}
		return
	}
	if !decision.ExpiresAt.IsZero() && !decision.ExpiresAt.After(proof.VerifiedAt()) {
		httpapi.WriteProblem(response, http.StatusInternalServerError, "server_error", errors.New("resource: subscription policy returned a nonfuture expiry"))
		return
	}
	record := EventSubscription{
		EventID: claims.EventID, AgentProvider: claims.Issuer, Agent: claims.Subject,
		MaxUses: claims.MaxUses, SubscribeTokenSHA256: sha256.Sum256([]byte(compact)),
		RegistrationSHA256: eventRegistrationSHA256(compact, request.Header.Get("Content-Type"), proof.ExactBody()),
		Parameters:         proof.ExactBody(), ContentType: request.Header.Get("Content-Type"),
		RegisteredAt: proof.VerifiedAt(), ExpiresAt: decision.ExpiresAt.UTC().Truncate(time.Second),
	}
	retained, err := service.store.Commit(request.Context(), record)
	if err != nil {
		if errors.Is(err, ErrEventSubscriptionConflict) {
			httpapi.WriteProblem(response, http.StatusConflict, "event_subscription_conflict", err)
		} else {
			httpapi.WriteProblem(response, http.StatusInternalServerError, "server_error", err)
		}
		return
	}
	if retained.EventID != record.EventID || retained.AgentProvider != record.AgentProvider ||
		retained.RegistrationSHA256 != record.RegistrationSHA256 {
		httpapi.WriteProblem(response, http.StatusInternalServerError, "server_error", errors.New("resource: event store returned a mismatched registration"))
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusOK)
}

// subscribeRegistration is one verified registration request and its
// subscribe token.
type subscribeRegistration struct {
	compact string
	claims  events.SubscribeTokenClaims
	proof   signaturekey.VerifiedRequest
}

// verifySubscribeRegistration verifies one signed registration request and
// its subscribe token as Events Subscribe Token Verification requires: the
// token's type, discovery document, signature and expiry; its aud against
// this Resource; its cnf.jwk as the key that signed the request; and a
// nonempty eid. Every failure is answered 401 with Signature-Error, and false
// means the response was written.
func (service *EventService) verifySubscribeRegistration(
	response http.ResponseWriter,
	request *http.Request,
) (subscribeRegistration, bool) {
	// A request with content must cover content-digest; PrepareRequest adds
	// that requirement. A signed Content-Type is required whenever one is sent.
	var requiredComponents []string
	if request.Header.Get("Content-Type") != "" {
		requiredComponents = []string{"content-type"}
	}
	prepared, err := signaturekey.PrepareRequest(request, service.clock, signaturekey.VerifyOptions{
		AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeJWT},
		RequiredComponents: requiredComponents,
		MaxBodyBytes:       service.maxRegistrationBytes,
	})
	if err != nil {
		writeEventSignatureProblem(response, err)
		return subscribeRegistration{}, false
	}
	compact, ok := prepared.Credential().JWT()
	if !ok {
		writeSubscribeTokenProblem(response, errors.New("resource: subscribe-token JWT is required"))
		return subscribeRegistration{}, false
	}
	claims, err := events.VerifySubscribeToken(request.Context(), compact, service.keyResolver, service.clock)
	if err != nil {
		writeSubscribeTokenProblem(response, err)
		return subscribeRegistration{}, false
	}
	proof, err := prepared.Verify(claims.Confirmation.JWK)
	if err != nil {
		writeEventSignatureProblem(response, err)
		return subscribeRegistration{}, false
	}
	if err := proof.CheckIssuedAt(time.Unix(claims.IssuedAt, 0)); err != nil {
		writeEventSignatureProblem(response, err)
		return subscribeRegistration{}, false
	}
	if request.Header.Get("Content-Type") == "" && len(proof.ExactBody()) > 0 {
		httpapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", errors.New("resource: nonempty subscription parameters require content-type"))
		return subscribeRegistration{}, false
	}
	if err := events.ValidateSubscribeRegistration(claims, service.issuer, proof.PublicKey()); err != nil {
		writeSubscribeTokenProblem(response, err)
		return subscribeRegistration{}, false
	}
	return subscribeRegistration{compact: compact, claims: claims, proof: proof}, true
}

func eventRegistrationSHA256(compactToken, contentType string, parameters []byte) [sha256.Size]byte {
	digest := sha256.New()
	_, _ = digest.Write([]byte(compactToken))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(contentType))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(parameters)
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func requestTargetsEndpoint(request *http.Request, endpoint *url.URL) bool {
	if request == nil || request.URL == nil || endpoint == nil {
		return false
	}
	authority := request.Host
	if authority == "" {
		authority = request.URL.Host
	}
	if request.URL.Scheme != "" && !strings.EqualFold(request.URL.Scheme, endpoint.Scheme) {
		return false
	}
	requestPath := request.URL.EscapedPath()
	if requestPath == "" {
		requestPath = "/"
	}
	return strings.EqualFold(authority, endpoint.Host) &&
		requestPath == endpoint.EscapedPath() && request.URL.RawQuery == ""
}

func writeEventSignatureProblem(response http.ResponseWriter, err error) {
	failure := signaturekey.NormalizeError(err, signaturekey.ErrorInvalidSignature)
	httpapi.WriteProblem(response, http.StatusUnauthorized, string(failure.Code), failure)
}

// writeSubscribeTokenProblem answers a subscribe token that fails
// verification: 401 with Signature-Error invalid_jwt unless the failure names
// a more specific code, such as expired_jwt or unknown_key.
func writeSubscribeTokenProblem(response http.ResponseWriter, err error) {
	failure := signaturekey.NormalizeError(err, signaturekey.ErrorInvalidJWT)
	httpapi.WriteProblem(response, http.StatusUnauthorized, string(failure.Code), failure)
}
