// Package revocation holds the token-revocation mechanics shared by the
// Person Server, Access Server and Resource roles: verifying a revocation
// caller, bounding what one caller may send, sending a signed revocation and
// polling its pending URL, and tracking a cascade until each downstream
// revocation has a terminal outcome. Each role keeps its own revocation state
// and decides what a revocation means for the tokens it holds.
package revocation

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const (
	// DefaultHold is how long a recipient holds a revocation open for its
	// cascade when the caller states no Prefer: wait. It covers one round
	// trip to each downstream party.
	DefaultHold = 20 * time.Second
	// DefaultRetryAfter is the polling interval a pending revocation names.
	DefaultRetryAfter = 5 * time.Second
	// Skew is how long past a revoked token's exp a recipient keeps the
	// revocation, so a presentation verified with a slower clock is refused.
	Skew = time.Minute

	defaultRequests    = 60
	defaultWindow      = time.Minute
	defaultMaxLifetime = 24 * time.Hour
)

// Limits returns limits with each zero member replaced by its default.
func Limits(limits aauth.RevocationLimits) aauth.RevocationLimits {
	if limits.Requests <= 0 {
		limits.Requests = defaultRequests
	}
	if limits.Window <= 0 {
		limits.Window = defaultWindow
	}
	if limits.MaxLifetime <= 0 {
		limits.MaxLifetime = defaultMaxLifetime
	}
	return limits
}

// ValidateLimits refuses negative limits, which have no meaning.
func ValidateLimits(limits aauth.RevocationLimits) error {
	if limits.Requests < 0 || limits.Window < 0 || limits.MaxLifetime < 0 {
		return errors.New("revocation limits must not be negative")
	}
	return nil
}

// Caller is the verified server identity that signed a revocation request or
// a poll of its pending URL.
type Caller struct {
	Issuer   string
	Document string
}

// VerifyCaller verifies a jwks_uri request proof whose id is the signer's own
// issuer. components are the covered components required beyond the base
// set: content-type and content-digest for a revocation, none for a bodyless
// poll. A failure is a Signature-Key error for the 401 answer.
func VerifyCaller(
	request *http.Request,
	clock signaturekey.Clock,
	resolver signaturekey.KeyResolver,
	components []string,
	maxBodyBytes int64,
) (Caller, error) {
	prepared, err := signaturekey.PrepareRequest(request, clock, signaturekey.VerifyOptions{
		RequiredComponents: components,
		AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeJWKSURI},
		MaxBodyBytes:       maxBodyBytes,
	})
	if err != nil {
		return Caller{}, err
	}
	issuer, document, _, ok := prepared.Credential().JWKSURI()
	if !ok {
		return Caller{}, signaturekey.NewError(signaturekey.ErrorUnsupportedScheme, errors.New("a revocation caller signs as a server"))
	}
	proof, err := prepared.VerifyJWKSURI(request.Context(), resolver)
	if err != nil {
		return Caller{}, err
	}
	if proof.Signer() != issuer {
		return Caller{}, signaturekey.NewError(signaturekey.ErrorInvalidKey, errors.New("revocation signer does not match its issuer"))
	}
	return Caller{Issuer: issuer, Document: document}, nil
}

// DecodeRequest reads one application/json revocation body whose issuer is
// the verified caller. It refuses an exp more than limits.MaxLifetime after
// now, since no token the recipient accepts lives that long.
func DecodeRequest(request *http.Request, issuer string, maxBytes int64, now time.Time, limits aauth.RevocationLimits) (aauth.RevocationRequest, error) {
	if mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type")); err != nil || mediaType != "application/json" {
		return aauth.RevocationRequest{}, errors.New("revocation request must be application/json")
	}
	decoded, err := aauth.DecodeRevocationRequest(request.Body, maxBytes, issuer)
	if err != nil {
		return aauth.RevocationRequest{}, err
	}
	if decoded.ExpiresAt.After(now.Add(Limits(limits).MaxLifetime)) {
		return aauth.RevocationRequest{}, errors.New("revocation exp is later than any token this recipient accepts")
	}
	return decoded, nil
}

// Hold is how long to hold a revocation open: the caller's Prefer: wait,
// capped at limit, or limit when the caller states none. A zero limit selects
// DefaultHold.
func Hold(request *http.Request, limit time.Duration) time.Duration {
	if limit <= 0 {
		limit = DefaultHold
	}
	if wait, ok := httpapi.ParsePreferWait(request.Header.Values("Prefer")); ok && wait < limit {
		return wait
	}
	return limit
}

// WriteReport answers a terminal revocation: 200 with the downstream report,
// or with no body and no Content-Type when there is nothing to report.
func WriteReport(response http.ResponseWriter, downstream []aauth.DownstreamRevocation) {
	body, err := aauth.EncodeRevocationReport(downstream)
	if err != nil {
		httpapi.WriteProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if len(body) == 0 {
		response.WriteHeader(http.StatusOK)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(body)
}

// WritePending answers a revocation whose cascade is not yet terminal. No
// AAuth-Requirement is used.
func WritePending(response http.ResponseWriter, location string, retryAfter time.Duration) {
	response.Header().Set("Location", location)
	response.Header().Set("Retry-After", seconds(retryAfter))
	response.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(response, http.StatusAccepted, map[string]string{"status": "pending"})
}

// WriteRateLimited answers 429 rate_limited with its required Retry-After.
func WriteRateLimited(response http.ResponseWriter, retryAfter time.Duration, cause error) {
	if retryAfter < time.Second {
		retryAfter = time.Second
	}
	response.Header().Set("Retry-After", seconds(retryAfter))
	response.Header().Set("Cache-Control", "no-store")
	httpapi.WriteProblem(response, http.StatusTooManyRequests, "rate_limited", cause)
}

// WriteUnknownPending answers a poll of a pending URL that does not exist or
// belongs to another caller, with an empty 404.
func WriteUnknownPending(response http.ResponseWriter) {
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusNotFound)
}

// WriteGone answers a poll after the pending URL returned its terminal
// response.
func WriteGone(response http.ResponseWriter) {
	response.Header().Set("Cache-Control", "no-store")
	httpapi.WriteProblem(response, http.StatusGone, "invalid_code", errors.New("revocation pending URL already returned its terminal response"))
}

// RequireEmptyBody reports whether a poll carried no body, as a poll must.
func RequireEmptyBody(request *http.Request) bool {
	if request.Body == nil || request.Body == http.NoBody {
		return true
	}
	var probe [1]byte
	read, _ := io.ReadFull(request.Body, probe[:])
	return read == 0
}

// ExpiredTokenReference returns the issuer and jti of a compact token whose
// verification failed only because it expired. Verification checks the
// signature before the lifetime, so the identity it returns was signed. It
// reports false for any other failure, so a revoked token is reported as
// revoked rather than expired without trusting unsigned claims.
func ExpiredTokenReference(compact string, err error) (aauth.TokenReference, bool) {
	var validation *aauth.TokenValidationError
	if !errors.As(err, &validation) || validation.Code != aauth.TokenValidationExpired {
		return aauth.TokenReference{}, false
	}
	parsed, parseErr := jose.ParseCompact(compact)
	if parseErr != nil {
		return aauth.TokenReference{}, false
	}
	var claims struct {
		Issuer string `json:"iss"`
		JTI    string `json:"jti"`
	}
	if json.Unmarshal(parsed.Payload(), &claims) != nil || claims.Issuer == "" || claims.JTI == "" {
		return aauth.TokenReference{}, false
	}
	return aauth.TokenReference{Issuer: claims.Issuer, JTI: claims.JTI}, true
}

// TokenReference returns the issuer and jti of a compact token that the
// caller has already verified.
func TokenReference(compact string) (aauth.TokenReference, error) {
	parsed, err := jose.ParseCompact(compact)
	if err != nil {
		return aauth.TokenReference{}, err
	}
	var claims struct {
		Issuer string `json:"iss"`
		JTI    string `json:"jti"`
	}
	if err := json.Unmarshal(parsed.Payload(), &claims); err != nil {
		return aauth.TokenReference{}, fmt.Errorf("decode token identity: %w", err)
	}
	reference := aauth.TokenReference{Issuer: claims.Issuer, JTI: claims.JTI}
	if err := aauth.ValidateTokenReference(reference); err != nil {
		return aauth.TokenReference{}, err
	}
	return reference, nil
}

func seconds(delay time.Duration) string {
	if delay <= 0 {
		return "0"
	}
	return fmt.Sprint(int64(math.Ceil(delay.Seconds())))
}
