package reference

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	aa "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// BudgetUsageClientErrorCode classifies client-side discovery, transport, and
// response failures without requiring callers to inspect local diagnostics.
type BudgetUsageClientErrorCode string

const (
	BudgetUsageClientInvalid      BudgetUsageClientErrorCode = "invalid"
	BudgetUsageClientUnavailable  BudgetUsageClientErrorCode = "unavailable"
	BudgetUsageClientUnauthorized BudgetUsageClientErrorCode = "unauthorized"
	BudgetUsageClientBadResponse  BudgetUsageClientErrorCode = "bad_response"
	BudgetUsageClientBadSignature BudgetUsageClientErrorCode = "bad_signature"
)

// BudgetUsageClientError retains a stable class beside its local cause.
type BudgetUsageClientError struct {
	Code  BudgetUsageClientErrorCode
	Cause error
}

func (err *BudgetUsageClientError) Error() string {
	if err == nil {
		return "reference: Budget usage client error"
	}
	if err.Cause == nil {
		return "reference: Budget usage client " + string(err.Code)
	}
	return "reference: Budget usage client " + string(err.Code) + ": " + err.Cause.Error()
}

func (err *BudgetUsageClientError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Cause
}

// BudgetUsageClient submits signed person-server usage queries and verifies
// the resource's request-bound response signature before decoding counters.
type BudgetUsageClient struct {
	httpClient   *http.Client
	personServer string
	signingKey   jose.SigningKey
	keyResolver  signaturekey.KeyResolver
	clock        aa.Clock
}

// BudgetUsageClientConfig supplies the caller's person-server identity and
// HTTP trust boundary. KeyResolver resolves the resource key named by the
// response's Signature-Key header.
type BudgetUsageClientConfig struct {
	Client       *http.Client
	PersonServer string
	SigningKey   jose.SigningKey
	KeyResolver  signaturekey.KeyResolver
	Clock        aa.Clock
}

// NewBudgetUsageClient validates a complete signed usage-query client.
func NewBudgetUsageClient(config BudgetUsageClientConfig) (*BudgetUsageClient, error) {
	if config.Client == nil {
		return nil, &BudgetUsageClientError{Code: BudgetUsageClientInvalid, Cause: errors.New("HTTP client is required")}
	}
	if err := aa.ValidateServerIdentifier(config.PersonServer); err != nil {
		return nil, &BudgetUsageClientError{Code: BudgetUsageClientInvalid, Cause: err}
	}
	if config.SigningKey.ID() == "" {
		return nil, &BudgetUsageClientError{Code: BudgetUsageClientInvalid, Cause: errors.New("person-server signing key is required")}
	}
	if config.KeyResolver == nil {
		return nil, &BudgetUsageClientError{Code: BudgetUsageClientInvalid, Cause: errors.New("resource response key resolver is required")}
	}
	if config.Clock == nil {
		return nil, &BudgetUsageClientError{Code: BudgetUsageClientInvalid, Cause: errors.New("clock is required")}
	}
	return &BudgetUsageClient{
		httpClient: config.Client, personServer: config.PersonServer, signingKey: config.SigningKey,
		keyResolver: config.KeyResolver, clock: config.Clock,
	}, nil
}

// Query discovers a resource's usage endpoint, submits the canonical signed
// scope/key query, and returns counters only after response signature and
// echoed-request validation succeed.
func (client *BudgetUsageClient) Query(ctx context.Context, resource string, query BudgetUsageQuery) (BudgetUsageSnapshot, error) {
	var snapshot BudgetUsageSnapshot
	if client == nil || client.httpClient == nil || client.keyResolver == nil || client.clock == nil {
		return snapshot, &BudgetUsageClientError{Code: BudgetUsageClientInvalid, Cause: errors.New("client is not initialized")}
	}
	if ctx == nil {
		return snapshot, &BudgetUsageClientError{Code: BudgetUsageClientInvalid, Cause: errors.New("context is required")}
	}
	if err := aa.ValidateServerIdentifier(resource); err != nil {
		return snapshot, &BudgetUsageClientError{Code: BudgetUsageClientInvalid, Cause: err}
	}
	if query.PersonServer != "" && query.PersonServer != client.personServer {
		return snapshot, &BudgetUsageClientError{Code: BudgetUsageClientInvalid, Cause: errors.New("query person server does not match client identity")}
	}
	query.PersonServer = client.personServer
	if err := query.Validate(); err != nil {
		return snapshot, &BudgetUsageClientError{Code: BudgetUsageClientInvalid, Cause: err}
	}
	metadata, err := client.discover(ctx, resource)
	if err != nil {
		return snapshot, err
	}
	body, err := json.Marshal(query)
	if err != nil {
		return snapshot, &BudgetUsageClientError{Code: BudgetUsageClientInvalid, Cause: err}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, metadata.UsageEndpoint, bytes.NewReader(body))
	if err != nil {
		return snapshot, &BudgetUsageClientError{Code: BudgetUsageClientInvalid, Cause: err}
	}
	request.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignJWKSURIRequest(request, client.signingKey, client.personServer, aa.PersonDiscoveryDocument, client.clock); err != nil {
		return snapshot, &BudgetUsageClientError{Code: BudgetUsageClientInvalid, Cause: err}
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return snapshot, &BudgetUsageClientError{Code: BudgetUsageClientUnavailable, Cause: err}
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxJSONBody+1))
		code := BudgetUsageClientBadResponse
		if response.StatusCode == http.StatusForbidden {
			code = BudgetUsageClientUnauthorized
		}
		return snapshot, &BudgetUsageClientError{Code: code, Cause: fmt.Errorf("usage endpoint returned HTTP %d", response.StatusCode)}
	}
	prepared, err := signaturekey.PrepareResponse(response, request, client.clock, signaturekey.ResponseVerifyOptions{})
	if err != nil {
		return snapshot, &BudgetUsageClientError{Code: BudgetUsageClientBadSignature, Cause: err}
	}
	issuer, document, keyID, ok := prepared.Credential().JWKSURI()
	if !ok || issuer != metadata.Issuer || issuer != resource || document != aa.ResourceDiscoveryDocument || keyID == "" {
		return snapshot, &BudgetUsageClientError{Code: BudgetUsageClientBadSignature, Cause: errors.New("usage response credential does not identify the requested resource")}
	}
	resourceKey, err := client.keyResolver.ResolveKey(ctx, issuer, document, keyID)
	if err != nil {
		return snapshot, &BudgetUsageClientError{Code: BudgetUsageClientBadSignature, Cause: signaturekey.NormalizeResolutionError(err)}
	}
	verified, err := prepared.Verify(resourceKey)
	if err != nil {
		return snapshot, &BudgetUsageClientError{Code: BudgetUsageClientBadSignature, Cause: err}
	}
	if verified.Status() != http.StatusOK || verified.Signer() != resource {
		return snapshot, &BudgetUsageClientError{Code: BudgetUsageClientBadSignature, Cause: errors.New("usage response status or signer is invalid")}
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxJSONBody+1))
	if err != nil {
		return snapshot, &BudgetUsageClientError{Code: BudgetUsageClientUnavailable, Cause: err}
	}
	if len(responseBody) > maxJSONBody {
		return snapshot, &BudgetUsageClientError{Code: BudgetUsageClientBadResponse, Cause: errors.New("usage response is too large")}
	}
	snapshot, err = decodeBudgetUsageResponse(responseBody, query, client.personServer, client.clock.Now().UTC())
	if err != nil {
		return snapshot, &BudgetUsageClientError{Code: BudgetUsageClientBadResponse, Cause: err}
	}
	return snapshot, nil
}

type budgetUsageMetadata struct {
	Issuer        string
	UsageEndpoint string
	JWKSURI       string
}

func (client *BudgetUsageClient) discover(ctx context.Context, resource string) (budgetUsageMetadata, error) {
	var metadata budgetUsageMetadata
	endpoint := resource + "/.well-known/" + aa.ResourceDiscoveryDocument
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return metadata, &BudgetUsageClientError{Code: BudgetUsageClientInvalid, Cause: err}
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.httpClient.Do(request)
	if err != nil {
		return metadata, &BudgetUsageClientError{Code: BudgetUsageClientUnavailable, Cause: err}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxJSONBody+1))
		return metadata, &BudgetUsageClientError{Code: BudgetUsageClientUnavailable, Cause: fmt.Errorf("resource metadata endpoint returned HTTP %d", response.StatusCode)}
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxJSONBody+1))
	if err != nil {
		return metadata, &BudgetUsageClientError{Code: BudgetUsageClientUnavailable, Cause: err}
	}
	if len(body) > maxJSONBody {
		return metadata, &BudgetUsageClientError{Code: BudgetUsageClientInvalid, Cause: errors.New("resource metadata is too large")}
	}
	var raw map[string]json.RawMessage
	if err := decodeJSONBytes(bytes.NewReader(body), &raw); err != nil {
		return metadata, &BudgetUsageClientError{Code: BudgetUsageClientInvalid, Cause: err}
	}
	if err := metadataString(raw, "issuer", &metadata.Issuer); err != nil || metadata.Issuer != resource {
		if err == nil {
			err = errors.New("resource metadata issuer does not match the requested resource")
		}
		return metadata, &BudgetUsageClientError{Code: BudgetUsageClientInvalid, Cause: err}
	}
	if err := metadataString(raw, "usage_endpoint", &metadata.UsageEndpoint); err != nil {
		return metadata, &BudgetUsageClientError{Code: BudgetUsageClientInvalid, Cause: err}
	}
	if _, err := budgetUsageEndpointPath(resource, metadata.UsageEndpoint); err != nil {
		return metadata, &BudgetUsageClientError{Code: BudgetUsageClientInvalid, Cause: err}
	}
	if err := metadataString(raw, "jwks_uri", &metadata.JWKSURI); err != nil {
		return metadata, &BudgetUsageClientError{Code: BudgetUsageClientBadSignature, Cause: err}
	}
	if err := validateResourceJWKSURI(resource, metadata.JWKSURI); err != nil {
		return metadata, &BudgetUsageClientError{Code: BudgetUsageClientBadSignature, Cause: err}
	}
	return metadata, nil
}

func metadataString(raw map[string]json.RawMessage, name string, destination *string) error {
	value, ok := raw[name]
	if !ok || json.Unmarshal(value, destination) != nil || *destination == "" || strings.TrimSpace(*destination) != *destination {
		return fmt.Errorf("resource metadata %s must be a non-empty string", name)
	}
	return nil
}

func validateResourceJWKSURI(resource, identifier string) error {
	resourceURL, err := url.Parse(resource)
	if err != nil {
		return err
	}
	keyURL, err := url.Parse(identifier)
	if err != nil || keyURL.Scheme != "https" || keyURL.Host != resourceURL.Host || keyURL.User != nil || keyURL.RawQuery != "" || keyURL.Fragment != "" || keyURL.Path == "" || keyURL.Path == "/" {
		return errors.New("resource metadata jwks_uri must be an HTTPS URL on the resource origin")
	}
	return nil
}

type budgetUsageResponseWire struct {
	AsOf        int64                `json:"as_of"`
	Audience    string               `json:"aud"`
	Unit        string               `json:"unit"`
	Decimals    int64                `json:"decimals"`
	Subject     *string              `json:"sub,omitempty"`
	Tenant      *string              `json:"tenant,omitempty"`
	MissionS256 *string              `json:"mission_s256,omitempty"`
	Usage       *BudgetUsageCounters `json:"usage,omitempty"`
	ByKey       map[string]int64     `json:"jkts,omitempty"`
}

func decodeBudgetUsageResponse(body []byte, query BudgetUsageQuery, personServer string, now time.Time) (BudgetUsageSnapshot, error) {
	var snapshot BudgetUsageSnapshot
	var raw map[string]json.RawMessage
	if err := decodeJSONBytes(bytes.NewReader(body), &raw); err != nil {
		return snapshot, err
	}
	var wire budgetUsageResponseWire
	if err := decodeJSONBytes(bytes.NewReader(body), &wire); err != nil {
		return snapshot, err
	}
	if wire.AsOf <= 0 || now.IsZero() || wire.AsOf > now.Unix() || wire.Audience != personServer || wire.Unit == "" || strings.TrimSpace(wire.Unit) != wire.Unit || wire.Decimals < 0 || wire.Decimals > budgets.MaxAmount {
		return snapshot, errors.New("usage response identity or denomination is invalid")
	}
	snapshot.AsOf, snapshot.Unit, snapshot.Decimals = wire.AsOf, wire.Unit, wire.Decimals
	if err := validateUsageEcho(raw, query, wire); err != nil {
		return snapshot, err
	}
	if wire.Usage != nil {
		usageRaw, ok := raw["usage"]
		if !ok {
			return snapshot, errors.New("usage response usage is malformed")
		}
		var usageMembers map[string]json.RawMessage
		if err := decodeJSONBytes(bytes.NewReader(usageRaw), &usageMembers); err != nil {
			return snapshot, err
		}
		if _, ok := usageMembers["all_time"]; !ok || validateUsageCounters(*wire.Usage) != nil {
			return snapshot, errors.New("usage response counters are invalid")
		}
		snapshot.Usage = wire.Usage
	} else if _, present := raw["usage"]; present {
		return snapshot, errors.New("usage response usage must be an object when present")
	}
	if query.AgentJKT != nil {
		if wire.ByKey == nil {
			return snapshot, errors.New("usage response jkts is required")
		}
		snapshot.ByKey = make(map[string]int64, len(wire.ByKey))
		for key, value := range wire.ByKey {
			if !usageKeyRequested(key, query.AgentJKT) || value < 0 || value > budgets.MaxAmount || !validRetainedThumbprint(key) {
				return snapshot, errors.New("usage response jkts contains an invalid or unrequested key")
			}
			snapshot.ByKey[key] = value
		}
	} else if _, present := raw["jkts"]; present {
		return snapshot, errors.New("usage response jkts must be omitted when not requested")
	}
	return snapshot, nil
}

func validateUsageEcho(raw map[string]json.RawMessage, query BudgetUsageQuery, wire budgetUsageResponseWire) error {
	check := func(name string, expected *string) error {
		_, exists := raw[name]
		if expected == nil {
			if exists {
				return fmt.Errorf("usage response unexpectedly echoes %s", name)
			}
			return nil
		}
		wireValue, ok := map[string]*string{"sub": wire.Subject, "tenant": wire.Tenant, "mission_s256": wire.MissionS256}[name]
		if !exists || !ok || wireValue == nil || *wireValue != *expected {
			return fmt.Errorf("usage response %s echo does not match the query", name)
		}
		return nil
	}
	if err := check("sub", nonEmptyPointer(query.Subject)); err != nil {
		return err
	}
	if err := check("tenant", nonEmptyPointer(query.Tenant)); err != nil {
		return err
	}
	if err := check("mission_s256", nonEmptyPointer(query.MissionS256)); err != nil {
		return err
	}
	return nil
}

func nonEmptyPointer(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func validateUsageCounters(counters BudgetUsageCounters) error {
	for _, value := range []int64{counters.Day, counters.Week, counters.Month, counters.Year, counters.AllTime} {
		if value < 0 || value > budgets.MaxAmount {
			return ErrBudgetUsageIntegrity
		}
	}
	return nil
}
