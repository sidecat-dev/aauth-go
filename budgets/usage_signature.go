package budgets

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// ErrUsageUnsigned reports a usage response that carries no signature when
// the caller required one.
var ErrUsageUnsigned = errors.New("budgets: usage response is not signed")

// UsageResponseSignOptions is the coverage of a signed usage response:
// @status, content-type and content-digest, bound to the request by
// @authority and @path under req. A Resource signs with these options and
// its jwks_uri key; VerifyUsageResponse requires the same coverage.
func UsageResponseSignOptions() signaturekey.ResponseSignOptions {
	return signaturekey.ResponseSignOptions{
		Components:        []string{"content-type", "content-digest"},
		RequestComponents: []string{"@authority", "@path"},
	}
}

// VerifyUsageResponse verifies a signed usage response: status, header and
// the exact body bytes the caller received, and request, the usage query the
// caller sent. The signature must cover what UsageResponseSignOptions covers
// and verify under a key from resource's own metadata, so a response signed
// by any other party, or for another request, is refused. The PS or AS that
// keeps the exact body and header holds a statement the resource cannot later
// disown.
func VerifyUsageResponse(
	ctx context.Context,
	request *http.Request,
	status int,
	header http.Header,
	body []byte,
	resource string,
	resolver signaturekey.KeyResolver,
	clock aauth.Clock,
) (signaturekey.VerifiedResponse, error) {
	if err := aauth.ValidateServerIdentifier(resource); err != nil {
		return signaturekey.VerifiedResponse{}, fmt.Errorf("budgets: usage resource: %w", err)
	}
	options := UsageResponseSignOptions()
	verified, err := signaturekey.VerifyResponse(ctx, status, header, body, request, resolver, clock, signaturekey.ResponseVerifyOptions{
		RequiredComponents:        options.Components,
		RequiredRequestComponents: options.RequestComponents,
	})
	if err != nil {
		return signaturekey.VerifiedResponse{}, fmt.Errorf("budgets: usage response signature: %w", err)
	}
	_, document, _, _ := verified.Credential().JWKSURI()
	if verified.Signer() != resource || document != aauth.ResourceDiscoveryDocument {
		return signaturekey.VerifiedResponse{}, errors.New("budgets: usage response is not signed by the resource that was asked")
	}
	return verified, nil
}

// UsageSignatureCheck tells PostUsageChecked how to treat the resource's
// response signature. Resource is the resource identifier whose
// usage_endpoint is called, and KeyResolver resolves its jwks_uri keys.
// Signing is RECOMMENDED rather than REQUIRED, so an unsigned response is
// read and reported as unsigned unless RequireSignature is set. A response
// that carries a signature which does not verify is always refused. Client
// defaults to one that refuses redirects.
type UsageSignatureCheck struct {
	Resource         string
	KeyResolver      signaturekey.KeyResolver
	RequireSignature bool
	Client           *http.Client
}

// UsageResult is a checked usage answer. Signed reports a verified resource
// signature. ExactBody and Header are the bytes and fields as received, so
// a caller can retain a signed statement as evidence.
type UsageResult struct {
	Response  UsageResponse
	Signed    bool
	ExactBody []byte
	Header    http.Header
}

// PostUsageChecked sends one signed usage query, as PostUsage does, and
// verifies the response signature per check before parsing the body.
func PostUsageChecked(
	ctx context.Context,
	endpoint string,
	key jose.SigningKey,
	caller string,
	discoveryDocument string,
	clock aauth.Clock,
	request UsageRequest,
	check UsageSignatureCheck,
) (UsageResult, error) {
	if check.KeyResolver == nil {
		return UsageResult{}, errors.New("budgets: usage signature check requires a key resolver")
	}
	exchange, err := postUsage(ctx, endpoint, key, caller, discoveryDocument, clock, request, check.Client)
	if err != nil {
		return UsageResult{}, err
	}
	signed := len(exchange.header.Values("Signature")) > 0 || len(exchange.header.Values("Signature-Input")) > 0
	if !signed && check.RequireSignature {
		return UsageResult{}, ErrUsageUnsigned
	}
	if signed {
		if _, err := VerifyUsageResponse(
			ctx, exchange.request, exchange.status, exchange.header, exchange.body,
			check.Resource, check.KeyResolver, clock,
		); err != nil {
			return UsageResult{}, err
		}
	}
	parsed, err := exchange.parse(request, caller)
	if err != nil {
		return UsageResult{}, err
	}
	return UsageResult{
		Response: parsed, Signed: signed,
		ExactBody: append([]byte(nil), exchange.body...), Header: exchange.header.Clone(),
	}, nil
}
