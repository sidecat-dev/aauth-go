package supervision

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// SignatureLabel is the label of a signed decision and of the Person
// Server's Accept-Signature request for one.
const SignatureLabel = "sig"

// AcceptSignature returns the Accept-Signature value a Person Server sends on
// a supervision request. A request with a body asks for its content-digest to
// be covered under req; a poll, which has none, asks for @authority and @path
// only.
func AcceptSignature(hasBody bool) string {
	if hasBody {
		return SignatureLabel + `=("@status" "content-type" "content-digest" "content-digest";req "@authority";req "@path";req)`
	}
	return SignatureLabel + `=("@status" "content-type" "content-digest" "@authority";req "@path";req)`
}

// DecisionSignOptions is the coverage of a signed decision answering request:
// @status, content-type and content-digest, bound to the request by its
// content-digest when it has one, and by @authority and @path.
func DecisionSignOptions(request *http.Request) signaturekey.ResponseSignOptions {
	requestComponents := []string{"@authority", "@path"}
	if request != nil && len(request.Header.Values("Content-Digest")) > 0 {
		requestComponents = []string{"content-digest", "@authority", "@path"}
	}
	return signaturekey.ResponseSignOptions{
		Label:             SignatureLabel,
		Components:        []string{"content-type", "content-digest"},
		RequestComponents: requestComponents,
	}
}

// SignDecision signs a terminal decision response under the SS's jwks_uri
// key, naming issuer and DiscoveryDocument in Signature-Key, and sets the
// signature and Content-Digest fields in header. body is the exact response
// body and request the request it answers.
func SignDecision(header http.Header, status int, body []byte, request *http.Request, key jose.SigningKey, issuer string, clock aauth.Clock) error {
	credential, err := signaturekey.NewJWKSURICredential(issuer, DiscoveryDocument, key.ID())
	if err != nil {
		return fmt.Errorf("supervision: decision signing credential: %w", err)
	}
	return signaturekey.SignResponse(header, status, body, request, key, credential, clock, DecisionSignOptions(request))
}

// VerifyDecision verifies a signed decision: the signature must cover
// @status, content-type and content-digest, verify under a key the
// supervisor's metadata names, and name supervisor as its Signature-Key id
// with DiscoveryDocument. window bounds how old the signature's created time
// may be; a decision repeated for an sdi already answered keeps its first
// signature, so a caller allows for the time since it first made the request.
func VerifyDecision(
	ctx context.Context,
	status int,
	header http.Header,
	body []byte,
	request *http.Request,
	supervisor string,
	resolver signaturekey.KeyResolver,
	clock aauth.Clock,
	window time.Duration,
) (signaturekey.VerifiedResponse, error) {
	verified, err := signaturekey.VerifyResponse(ctx, status, header, body, request, resolver, clock, signaturekey.ResponseVerifyOptions{
		Label:              SignatureLabel,
		RequiredComponents: []string{"content-type", "content-digest"},
		SignatureWindow:    window,
	})
	if err != nil {
		return signaturekey.VerifiedResponse{}, fmt.Errorf("supervision: decision signature: %w", err)
	}
	_, document, _, _ := verified.Credential().JWKSURI()
	if verified.Signer() != supervisor || document != DiscoveryDocument {
		return signaturekey.VerifiedResponse{}, errors.New("supervision: decision is not signed by the supervision server that was asked")
	}
	return verified, nil
}

// RecordedRequest is a request as the Person Server signed and sent it.
type RecordedRequest struct {
	Method string
	URL    string
	Header http.Header
	Body   []byte
}

// RecordedResponse is a response as the Person Server received it.
type RecordedResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

// Exchange is one request to an SS and the response to it, kept as the
// Person Server's log entry for a decision. ActAt is the time of the act, the
// request's iat; a poll carries no body, so it is recorded here. Response is
// nil when no response arrived. Signed reports that the response carried a
// signature that verified.
type Exchange struct {
	Supervisor string
	Request    RecordedRequest
	Response   *RecordedResponse
	ActAt      time.Time
	SentAt     time.Time
	ReceivedAt time.Time
	Signed     bool
}

// Clone returns an independent copy.
func (exchange Exchange) Clone() Exchange {
	exchange.Request.Header = exchange.Request.Header.Clone()
	exchange.Request.Body = append([]byte(nil), exchange.Request.Body...)
	if exchange.Response != nil {
		response := *exchange.Response
		response.Header = response.Header.Clone()
		response.Body = append([]byte(nil), response.Body...)
		exchange.Response = &response
	}
	return exchange
}

// VerifyExchange verifies a recorded signed decision again, for a party who
// reads the log entry later and was not on the connection. The response
// identifies its signer in itself, so the check needs only the record and a
// key resolver; it does not depend on which SS was configured at the time.
// Verification uses the recorded receipt time, and allows a signature as old
// as the act, for a decision the SS repeated.
func VerifyExchange(ctx context.Context, exchange Exchange, resolver signaturekey.KeyResolver) (signaturekey.VerifiedResponse, error) {
	if exchange.Response == nil {
		return signaturekey.VerifiedResponse{}, errors.New("supervision: the exchange has no response")
	}
	request, err := http.NewRequestWithContext(ctx, exchange.Request.Method, exchange.Request.URL, bytes.NewReader(exchange.Request.Body))
	if err != nil {
		return signaturekey.VerifiedResponse{}, fmt.Errorf("supervision: recorded request: %w", err)
	}
	request.Header = exchange.Request.Header.Clone()
	at := exchange.ReceivedAt
	clock := aauth.ClockFunc(func() time.Time { return at })
	return VerifyDecision(ctx, exchange.Response.Status, exchange.Response.Header, exchange.Response.Body,
		request, exchange.Supervisor, resolver, clock, decisionWindow(exchange.ActAt, at))
}

// decisionWindow allows a signed decision created any time since the act,
// plus the ordinary signature window.
func decisionWindow(actAt, at time.Time) time.Duration {
	window := signaturekey.DefaultSignatureWindow
	if since := at.Sub(actAt); !actAt.IsZero() && since > 0 {
		window += since
	}
	return window
}
