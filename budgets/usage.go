package budgets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"unicode/utf8"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// ErrUsageRequest marks a usage body the endpoint rejects as invalid_request.
var ErrUsageRequest = errors.New("budgets: usage request is invalid")

// UsageRequest is the JSON body of a signed usage query. At most one of
// Subject, Tenant, and MissionS256 is set. JKTs may accompany that scope key
// or stand alone. PersonServer is the ps member an Access Server sends with a
// scope key; a Person Server omits it.
type UsageRequest struct {
	Subject      string
	Tenant       string
	MissionS256  string
	PersonServer string
	JKTs         []string
}

// UsageCalendar holds the counters a resource chose to report. AllTime is
// required when the usage object is present. A nil period was omitted.
type UsageCalendar struct {
	Day     *int64
	Week    *int64
	Month   *int64
	Year    *int64
	AllTime int64
}

// UsageResponse is one usage-endpoint success body.
type UsageResponse struct {
	AsOf        int64
	Audience    string
	Unit        Unit
	Subject     string
	Tenant      string
	MissionS256 string
	Usage       *UsageCalendar
	JKTs        map[string]int64
	JKTsPresent bool
}

type usageRequestWire struct {
	Subject      json.RawMessage `json:"sub"`
	Tenant       json.RawMessage `json:"tenant"`
	MissionS256  json.RawMessage `json:"mission_s256"`
	PersonServer json.RawMessage `json:"ps"`
	JKTs         json.RawMessage `json:"jkts"`
}

type usageResponseWire struct {
	AsOf        *int64             `json:"as_of"`
	Audience    *string            `json:"aud"`
	Unit        *string            `json:"unit"`
	Decimals    *int64             `json:"decimals"`
	Subject     *string            `json:"sub"`
	Tenant      *string            `json:"tenant"`
	MissionS256 *string            `json:"mission_s256"`
	Usage       *usageCalendarWire `json:"usage"`
	JKTs        map[string]*int64  `json:"jkts"`
}

type usageCalendarWire struct {
	Day     *int64 `json:"day"`
	Week    *int64 `json:"week"`
	Month   *int64 `json:"month"`
	Year    *int64 `json:"year"`
	AllTime *int64 `json:"all_time"`
}

// ParseUsageRequest accepts one strict usage-request object.
func ParseUsageRequest(data []byte) (UsageRequest, error) {
	var wire usageRequestWire
	if err := decodeStrictJSON(data, &wire); err != nil {
		return UsageRequest{}, fmt.Errorf("%w: %v", ErrUsageRequest, err)
	}
	request := UsageRequest{}
	var err error
	if request.Subject, err = usageString(wire.Subject, "sub"); err != nil {
		return UsageRequest{}, err
	}
	if request.Tenant, err = usageString(wire.Tenant, "tenant"); err != nil {
		return UsageRequest{}, err
	}
	if request.MissionS256, err = usageString(wire.MissionS256, "mission_s256"); err != nil {
		return UsageRequest{}, err
	}
	if request.PersonServer, err = usageString(wire.PersonServer, "ps"); err != nil {
		return UsageRequest{}, err
	}
	if request.JKTs, err = usageThumbprints(wire.JKTs); err != nil {
		return UsageRequest{}, err
	}
	if err := request.validate(); err != nil {
		return UsageRequest{}, err
	}
	return request, nil
}

// HasScope reports whether the request names sub, tenant, or mission_s256.
func (request UsageRequest) HasScope() bool {
	return request.Subject != "" || request.Tenant != "" || request.MissionS256 != ""
}

func (request UsageRequest) validate() error {
	scopes := 0
	if request.Subject != "" {
		scopes++
	}
	if request.Tenant != "" {
		scopes++
	}
	if request.MissionS256 != "" {
		scopes++
	}
	if scopes > 1 || (scopes == 0 && len(request.JKTs) == 0) {
		return fmt.Errorf("%w: a usage request needs one scope key, jkts, or both", ErrUsageRequest)
	}
	if request.PersonServer != "" {
		if err := aauth.ValidateServerIdentifier(request.PersonServer); err != nil {
			return fmt.Errorf("%w: ps: %v", ErrUsageRequest, err)
		}
	}
	seen := make(map[string]struct{}, len(request.JKTs))
	for _, thumbprint := range request.JKTs {
		if _, duplicate := seen[thumbprint]; duplicate {
			return fmt.Errorf("%w: duplicate jkt", ErrUsageRequest)
		}
		seen[thumbprint] = struct{}{}
		if err := validateThumbprint(thumbprint); err != nil {
			return err
		}
	}
	return nil
}

func (request UsageRequest) MarshalJSON() ([]byte, error) {
	if err := request.validate(); err != nil {
		return nil, err
	}
	payload := map[string]any{}
	if request.Subject != "" {
		payload["sub"] = request.Subject
	}
	if request.Tenant != "" {
		payload["tenant"] = request.Tenant
	}
	if request.MissionS256 != "" {
		payload["mission_s256"] = request.MissionS256
	}
	if request.PersonServer != "" {
		payload["ps"] = request.PersonServer
	}
	if len(request.JKTs) > 0 {
		payload["jkts"] = append([]string(nil), request.JKTs...)
	}
	return json.Marshal(payload)
}

// ParseUsageResponse accepts one strict usage success body.
func ParseUsageResponse(data []byte) (UsageResponse, error) {
	var wire usageResponseWire
	if err := decodeStrictJSON(data, &wire); err != nil {
		return UsageResponse{}, fmt.Errorf("budgets: usage response: %w", err)
	}
	if wire.AsOf == nil || *wire.AsOf < 0 {
		return UsageResponse{}, errors.New("budgets: usage response as_of is required")
	}
	if wire.Audience == nil || *wire.Audience == "" {
		return UsageResponse{}, errors.New("budgets: usage response aud is required")
	}
	if err := aauth.ValidateServerIdentifier(*wire.Audience); err != nil {
		return UsageResponse{}, fmt.Errorf("budgets: usage response aud: %w", err)
	}
	if wire.Unit == nil || wire.Decimals == nil {
		return UsageResponse{}, errors.New("budgets: usage response unit and decimals are required")
	}
	unit, err := NewUnit(*wire.Unit, *wire.Decimals)
	if err != nil {
		return UsageResponse{}, fmt.Errorf("budgets: usage response unit: %w", err)
	}
	response := UsageResponse{AsOf: *wire.AsOf, Audience: *wire.Audience, Unit: unit}
	if response.Subject, err = optionalUsageString(wire.Subject, "sub"); err != nil {
		return UsageResponse{}, err
	}
	if response.Tenant, err = optionalUsageString(wire.Tenant, "tenant"); err != nil {
		return UsageResponse{}, err
	}
	if response.MissionS256, err = optionalUsageString(wire.MissionS256, "mission_s256"); err != nil {
		return UsageResponse{}, err
	}
	scopes := 0
	if response.Subject != "" {
		scopes++
	}
	if response.Tenant != "" {
		scopes++
	}
	if response.MissionS256 != "" {
		scopes++
	}
	if scopes > 1 {
		return UsageResponse{}, errors.New("budgets: usage response carries more than one scope key")
	}
	if wire.Usage != nil {
		if wire.Usage.AllTime == nil {
			return UsageResponse{}, errors.New("budgets: usage response all_time is required")
		}
		calendar := UsageCalendar{AllTime: *wire.Usage.AllTime}
		for _, counter := range []struct {
			name  string
			value *int64
			dest  **int64
		}{
			{"all_time", wire.Usage.AllTime, nil},
			{"day", wire.Usage.Day, &calendar.Day},
			{"week", wire.Usage.Week, &calendar.Week},
			{"month", wire.Usage.Month, &calendar.Month},
			{"year", wire.Usage.Year, &calendar.Year},
		} {
			if counter.value == nil {
				continue
			}
			if err := validateAmount(counter.name, *counter.value); err != nil {
				return UsageResponse{}, fmt.Errorf("budgets: usage response: %w", err)
			}
			if counter.dest != nil {
				copied := *counter.value
				*counter.dest = &copied
			}
		}
		response.Usage = &calendar
	}
	if wire.JKTs != nil {
		response.JKTsPresent = true
		response.JKTs = make(map[string]int64, len(wire.JKTs))
		for thumbprint, amount := range wire.JKTs {
			if err := validateThumbprint(thumbprint); err != nil {
				return UsageResponse{}, err
			}
			if amount == nil {
				return UsageResponse{}, errors.New("budgets: usage response jkt amount is required")
			}
			if err := validateAmount("jkt", *amount); err != nil {
				return UsageResponse{}, fmt.Errorf("budgets: usage response: %w", err)
			}
			response.JKTs[thumbprint] = *amount
		}
	}
	return response, nil
}

// CheckUsageResponse reports whether a success body answers this request for
// this caller. An omitted usage object is a valid answer to a scope key.
func CheckUsageResponse(request UsageRequest, caller string, response UsageResponse) error {
	if response.Audience != caller {
		return errors.New("budgets: usage response aud does not name the caller")
	}
	if response.Subject != request.Subject || response.Tenant != request.Tenant || response.MissionS256 != request.MissionS256 {
		return errors.New("budgets: usage response does not echo the requested scope key")
	}
	if !request.HasScope() && response.Usage != nil {
		return errors.New("budgets: usage response carries usage without a scope key")
	}
	if len(request.JKTs) == 0 {
		if response.JKTsPresent {
			return errors.New("budgets: usage response carries jkts that were not requested")
		}
		return nil
	}
	if !response.JKTsPresent {
		return errors.New("budgets: usage response omits requested jkts")
	}
	asked := make(map[string]struct{}, len(request.JKTs))
	for _, thumbprint := range request.JKTs {
		asked[thumbprint] = struct{}{}
	}
	for thumbprint := range response.JKTs {
		if _, ok := asked[thumbprint]; !ok {
			return fmt.Errorf("budgets: usage response names an unrequested jkt %s", thumbprint)
		}
	}
	return nil
}

// PostUsage sends one signed usage query and parses the success body. It
// does not check a response signature; PostUsageChecked does. A nil client
// refuses redirects.
func PostUsage(
	ctx context.Context,
	endpoint string,
	key jose.SigningKey,
	caller string,
	discoveryDocument string,
	clock aauth.Clock,
	request UsageRequest,
	client *http.Client,
) (UsageResponse, error) {
	exchange, err := postUsage(ctx, endpoint, key, caller, discoveryDocument, clock, request, client)
	if err != nil {
		return UsageResponse{}, err
	}
	return exchange.parse(request, caller)
}

// usageExchange is one usage query and the success response it received.
type usageExchange struct {
	request *http.Request
	status  int
	header  http.Header
	body    []byte
}

func (exchange usageExchange) parse(request UsageRequest, caller string) (UsageResponse, error) {
	parsed, err := ParseUsageResponse(exchange.body)
	if err != nil {
		return UsageResponse{}, err
	}
	if err := CheckUsageResponse(request, caller, parsed); err != nil {
		return UsageResponse{}, err
	}
	return parsed, nil
}

func postUsage(
	ctx context.Context,
	endpoint string,
	key jose.SigningKey,
	caller string,
	discoveryDocument string,
	clock aauth.Clock,
	request UsageRequest,
	client *http.Client,
) (usageExchange, error) {
	if err := aauth.ValidateEndpoint(endpoint); err != nil {
		return usageExchange{}, err
	}
	if err := request.validate(); err != nil {
		return usageExchange{}, err
	}
	if clock == nil {
		return usageExchange{}, errors.New("budgets: clock is required")
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return usageExchange{}, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return usageExchange{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignJWKSURIRequestWithOptions(
		httpRequest, key, caller, discoveryDocument, clock,
		signaturekey.SignOptions{
			AdditionalComponents: []string{"content-type", "content-digest"},
			MaxBodyBytes:         1 << 20,
		},
	); err != nil {
		return usageExchange{}, err
	}
	if client == nil {
		client = &http.Client{CheckRedirect: refuseUsageRedirect}
	}
	httpResponse, err := client.Do(httpRequest)
	if err != nil {
		return usageExchange{}, err
	}
	defer httpResponse.Body.Close()
	body, err := io.ReadAll(io.LimitReader(httpResponse.Body, 1<<20))
	if err != nil {
		return usageExchange{}, err
	}
	if httpResponse.StatusCode != http.StatusOK {
		return usageExchange{}, fmt.Errorf("budgets: usage endpoint returned %d", httpResponse.StatusCode)
	}
	return usageExchange{
		request: httpRequest, status: httpResponse.StatusCode,
		header: httpResponse.Header.Clone(), body: body,
	}, nil
}

func refuseUsageRedirect(*http.Request, []*http.Request) error {
	return errors.New("budgets: usage endpoint must not redirect")
}

func usageString(raw json.RawMessage, name string) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}
	if string(raw) == "null" {
		return "", fmt.Errorf("%w: %s is null", ErrUsageRequest, name)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("%w: %s must be a string", ErrUsageRequest, name)
	}
	if value == "" || !utf8.ValidString(value) || len(value) > 2048 {
		return "", fmt.Errorf("%w: %s is empty or too long", ErrUsageRequest, name)
	}
	return value, nil
}

func optionalUsageString(value *string, name string) (string, error) {
	if value == nil {
		return "", nil
	}
	if *value == "" || !utf8.ValidString(*value) {
		return "", fmt.Errorf("budgets: usage response %s is empty", name)
	}
	return *value, nil
}

func usageThumbprints(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if string(raw) == "null" {
		return nil, fmt.Errorf("%w: jkts is null", ErrUsageRequest)
	}
	var values []string
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&values); err != nil {
		return nil, fmt.Errorf("%w: jkts must be an array of strings", ErrUsageRequest)
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("%w: jkts is empty", ErrUsageRequest)
	}
	return values, nil
}

func validateThumbprint(value string) error {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return fmt.Errorf("%w: jkt must be an RFC 7638 SHA-256 thumbprint", ErrUsageRequest)
	}
	return nil
}
