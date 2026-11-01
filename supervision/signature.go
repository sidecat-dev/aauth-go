package supervision

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/dunglas/httpsfv"
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

// DecisionSignOptions is the coverage of a signed decision answering request.
// It always covers @status, content-type and content-digest. When request
// carries Accept-Signature, it then covers each further component the
// request names under SignatureLabel that the SS can produce, in the order
// named: signature-key, and under req @method, @authority, @path, @query
// when the request has a query, and request fields the request carries.
// Without Accept-Signature, it binds the decision to request by its
// content-digest when it has one, and by @authority and @path.
func DecisionSignOptions(request *http.Request) signaturekey.ResponseSignOptions {
	options := signaturekey.ResponseSignOptions{
		Label:      SignatureLabel,
		Components: []string{"content-type", "content-digest"},
	}
	if requested, ok := acceptedComponents(request); ok {
		for _, component := range requested {
			if !component.request {
				if component.name == "signature-key" {
					options.Components = append(options.Components, component.name)
				}
				continue
			}
			switch component.name {
			case "@method", "@authority", "@path":
			case "@query":
				if request.URL.RawQuery == "" {
					continue
				}
			default:
				if strings.HasPrefix(component.name, "@") || len(request.Header.Values(component.name)) == 0 {
					continue
				}
			}
			if !slices.Contains(options.RequestComponents, component.name) {
				options.RequestComponents = append(options.RequestComponents, component.name)
			}
		}
		return options
	}
	options.RequestComponents = []string{"@authority", "@path"}
	if request != nil && len(request.Header.Values("Content-Digest")) > 0 {
		options.RequestComponents = []string{"content-digest", "@authority", "@path"}
	}
	return options
}

type acceptedComponent struct {
	name    string
	request bool
}

// acceptedComponents reads the components request's Accept-Signature names
// under SignatureLabel. It reports false when there is none it can read.
func acceptedComponents(request *http.Request) ([]acceptedComponent, bool) {
	if request == nil {
		return nil, false
	}
	values := request.Header.Values("Accept-Signature")
	if len(values) == 0 {
		return nil, false
	}
	dictionary, err := httpsfv.UnmarshalDictionary(values)
	if err != nil {
		return nil, false
	}
	member, ok := dictionary.Get(SignatureLabel)
	if !ok {
		return nil, false
	}
	list, ok := member.(httpsfv.InnerList)
	if !ok {
		return nil, false
	}
	var components []acceptedComponent
	for _, item := range list.Items {
		name, ok := item.Value.(string)
		if !ok || name == "" || name != strings.ToLower(name) {
			return nil, false
		}
		component := acceptedComponent{name: name}
		if value, present := item.Params.Get("req"); present {
			if value != true {
				return nil, false
			}
			component.request = true
		}
		components = append(components, component)
	}
	return components, true
}

// SignDecision signs a terminal decision response under the SS's jwks_uri
// key, naming issuer and DiscoveryDocument in Signature-Key, and sets the
// signature and Content-Digest fields in header. Signature-Input carries
// created and the key's kid as keyid, as the draft's example does. body is
// the exact response body and request the request it answers.
func SignDecision(header http.Header, status int, body []byte, request *http.Request, key jose.SigningKey, issuer string, clock aauth.Clock) error {
	credential, err := signaturekey.NewJWKSURICredential(issuer, DiscoveryDocument, key.ID())
	if err != nil {
		return fmt.Errorf("supervision: decision signing credential: %w", err)
	}
	options := DecisionSignOptions(request)
	options.KeyID = key.ID()
	return signaturekey.SignResponse(header, status, body, request, key, credential, clock, options)
}

// VerifyDecision verifies a signed decision: the signature must cover
// @status, content-type and content-digest, verify under a key the
// supervisor's metadata names, and name supervisor as its Signature-Key id
// with DiscoveryDocument. Any covered req component is checked against
// request. A signature's created time has no lower bound: a repeated decision
// keeps its first signature, and one reached later at a pending URL is signed
// when polled. One more than the signature window ahead of clock is refused.
func VerifyDecision(
	ctx context.Context,
	status int,
	header http.Header,
	body []byte,
	request *http.Request,
	supervisor string,
	resolver signaturekey.KeyResolver,
	clock aauth.Clock,
) (signaturekey.VerifiedResponse, error) {
	verified, err := signaturekey.VerifyResponse(ctx, status, header, body, request, resolver, clock, signaturekey.ResponseVerifyOptions{
		Label:              SignatureLabel,
		RequiredComponents: []string{"content-type", "content-digest"},
		SignatureWindow:    unboundedSignatureAge,
	})
	if err != nil {
		return signaturekey.VerifiedResponse{}, fmt.Errorf("supervision: decision signature: %w", err)
	}
	if verified.Created().After(clock.Now().Add(signaturekey.DefaultSignatureWindow)) {
		return signaturekey.VerifiedResponse{}, errors.New("supervision: decision signature was created ahead of the signature window")
	}
	_, document, _, _ := verified.Credential().JWKSURI()
	if verified.Signer() != supervisor || document != DiscoveryDocument {
		return signaturekey.VerifiedResponse{}, errors.New("supervision: decision is not signed by the supervision server that was asked")
	}
	return verified, nil
}

// unboundedSignatureAge admits a decision signature of any age; VerifyDecision
// bounds only a created time ahead of the clock.
const unboundedSignatureAge = 100 * 365 * 24 * time.Hour

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
// Person Server's log entry for a decision. Response is nil when no response
// arrived. Signed reports that the response carried a signature that
// verified.
type Exchange struct {
	Supervisor string
	Request    RecordedRequest
	Response   *RecordedResponse
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
// Verification uses the recorded receipt time.
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
		request, exchange.Supervisor, resolver, clock)
}
