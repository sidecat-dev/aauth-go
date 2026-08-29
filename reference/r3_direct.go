package reference

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// R3Review is the person-server deployment's consent and policy boundary over
// the exact document fetched for one verified authorization request.
type R3Review func(context.Context, aauth.AuthorizationRequest, r3.DocumentReference) error

// R3GrantPolicy is the access-server deployment's direct-grant policy over the
// exact document fetched for one verified authorization request.
type R3GrantPolicy func(context.Context, aauth.AuthorizationRequest, r3.DocumentReference) (r3.OperationSet, error)

type r3FetchConfig struct {
	client            *http.Client
	key               jose.SigningKey
	identifier        string
	discoveryDocument string
	clock             aauth.Clock
	admit             func(context.Context, string) error
	timeout           time.Duration
}

func selectDirectR3Document(
	resourceIdentifier string,
	requested r3.OperationSet,
	exact []byte,
) (r3.DocumentReference, error) {
	if err := requested.Validate(); err != nil {
		return r3.DocumentReference{}, err
	}
	digest := r3.S256(exact)
	reference, err := r3.NewDocumentReference(resourceIdentifier+"/r3/"+digest, exact)
	if err != nil {
		return r3.DocumentReference{}, err
	}
	document, _ := reference.Document()
	if !document.OperationSet().Equal(requested) {
		return r3.DocumentReference{}, errors.New("selected direct R3 document must contain exactly the requested operations")
	}
	return reference, nil
}

func fetchR3Document(
	ctx context.Context,
	config r3FetchConfig,
	resourceIdentifier string,
	token r3.TokenResult,
) (r3.DocumentReference, error) {
	if config.client == nil || config.admit == nil || config.clock == nil || config.key.ID() == "" {
		return r3.DocumentReference{}, errors.New("reference: R3 fetch composition is incomplete")
	}
	if !token.Valid() {
		return r3.DocumentReference{}, errors.New("reference: R3 token result is invalid")
	}
	origin, err := endpointIdentifier(token.URI())
	if err != nil || origin != resourceIdentifier {
		return r3.DocumentReference{}, errors.New("reference: R3 document URI is not hosted by the resource-token issuer")
	}
	if err := config.admit(ctx, token.URI()); err != nil {
		return r3.DocumentReference{}, fmt.Errorf("reference: R3 fetch is not admitted: %w", err)
	}
	timeout := config.timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	if timeout < 0 {
		return r3.DocumentReference{}, errors.New("reference: R3 fetch timeout is invalid")
	}
	fetchContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(fetchContext, http.MethodGet, token.URI(), nil)
	if err != nil {
		return r3.DocumentReference{}, err
	}
	nonce := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return r3.DocumentReference{}, fmt.Errorf("reference: generate R3 fetch nonce: %w", err)
	}
	if err := signaturekey.SignJWKSURIRequestWithOptions(
		request,
		config.key,
		config.identifier,
		config.discoveryDocument,
		config.clock,
		signaturekey.SignOptions{Nonce: base64.RawURLEncoding.EncodeToString(nonce)},
	); err != nil {
		return r3.DocumentReference{}, err
	}
	client := *config.client
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return r3.DocumentReference{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return r3.DocumentReference{}, responseError(response)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return r3.DocumentReference{}, errors.New("reference: R3 document response must be application/json")
	}
	exact, err := io.ReadAll(io.LimitReader(response.Body, maxJSONBody+1))
	if err != nil {
		return r3.DocumentReference{}, err
	}
	if len(exact) > maxJSONBody {
		return r3.DocumentReference{}, errors.New("reference: R3 document response is too large")
	}
	return r3.VerifyDocument(token, exact)
}
