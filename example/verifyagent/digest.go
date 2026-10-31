package main

import (
	"net/http"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// digestEverywhereResource also requires a signed content-digest on requests
// with no body, and lists it in its metadata. An Agent that signs without
// reading the metadata is refused with invalid_input.
func digestEverywhereResource(keys signaturekey.KeyResolver, clock aauth.Clock, app http.Handler) (http.Handler, error) {
	server, err := resource.NewAgentIdentity(resource.AgentIdentityConfig{
		Issuer: "https://resource.example", KeyResolver: keys, Clock: clock,
		AdditionalSignatureComponents: []string{"content-digest"},
		Protected:                     app,
	})
	if err != nil {
		return nil, err
	}
	return server.Handler(), nil
}

// signAgentRequest covers content-digest whether or not the request has a body.
func signAgentRequest(request *http.Request, key jose.SigningKey, token string, clock aauth.Clock) error {
	return signaturekey.SignJWTRequestWithOptions(request, key, token, clock, signaturekey.SignOptions{
		AdditionalComponents: []string{"content-digest"},
	})
}
