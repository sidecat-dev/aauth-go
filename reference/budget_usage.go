package reference

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
	"net/url"
	"strings"
	"time"

	aa "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

var (
	ErrBudgetUsageStore          = errors.New("reference: Budget usage store is not initialized")
	ErrBudgetUsageUnauthorized   = errors.New("reference: Budget usage signer has no observed authorization")
	ErrBudgetUsageMixedUnits     = errors.New("reference: Budget usage query spans multiple denominations")
	ErrBudgetUsageIntegrity      = errors.New("reference: Budget usage state integrity check failed")
	ErrBudgetUsageInvalidRequest = errors.New("reference: Budget usage query is invalid")
)

// BudgetUsageRecord is the exact consumption evidence retained for one
// completed metered call. Key is the corresponding BudgetExecution key.
type BudgetUsageRecord struct {
	Key          string `json:"key"`
	PersonServer string `json:"person_server"`
	Subject      string `json:"subject"`
	Tenant       string `json:"tenant,omitempty"`
	MissionS256  string `json:"mission_s256,omitempty"`
	AgentJKT     string `json:"agent_jkt,omitempty"`
	Unit         string `json:"unit"`
	Decimals     int64  `json:"decimals"`
	Consumed     int64  `json:"consumed"`
	RecordedAt   int64  `json:"recorded_at"`
}

// BudgetUsageQuery selects one person-server scope and/or specific signing
// keys. PersonServer is supplied by the authenticated request signer.
type BudgetUsageQuery struct {
	PersonServer string   `json:"-"`
	Subject      string   `json:"sub,omitempty"`
	Tenant       string   `json:"tenant,omitempty"`
	MissionS256  string   `json:"mission_s256,omitempty"`
	AgentJKT     []string `json:"jkts,omitempty"`
}

// BudgetUsageCounters contains UTC calendar totals for one selected scope.
type BudgetUsageCounters struct {
	Day     int64 `json:"day,omitempty"`
	Week    int64 `json:"week,omitempty"`
	Month   int64 `json:"month,omitempty"`
	Year    int64 `json:"year,omitempty"`
	AllTime int64 `json:"all_time"`
}

// BudgetUsageSnapshot is the resource's response-independent projection of
// selected usage. A nil Usage means the scope was recognized but has no
// matching records; ByKey omits keys that have no retained figure.
type BudgetUsageSnapshot struct {
	AsOf     int64
	Unit     string
	Decimals int64
	Usage    *BudgetUsageCounters
	ByKey    map[string]int64
}

// BudgetUsageStore serves the resource's retained usage counters.
type BudgetUsageStore interface {
	Usage(context.Context, BudgetUsageQuery, time.Time) (BudgetUsageSnapshot, error)
}

// BudgetUsageRecorder is implemented by a BudgetStore that can atomically
// retain the completed result and its usage evidence in one state transition.
type BudgetUsageRecorder interface {
	CompleteWithUsage(context.Context, string, BudgetResult, BudgetUsageRecord) (BudgetRecord, int64, error)
}

// Validate checks the exact context and denomination of one usage record.
func (record BudgetUsageRecord) Validate() error {
	if !validBudgetExecutionKey(record.Key) || !validUsageIdentity(record.PersonServer) || !validUsageIdentity(record.Subject) ||
		(record.Tenant != "" && !validUsageIdentity(record.Tenant)) ||
		(record.MissionS256 != "" && !validRetainedThumbprint(record.MissionS256)) ||
		(record.AgentJKT != "" && !validRetainedThumbprint(record.AgentJKT)) ||
		record.Unit == "" || strings.TrimSpace(record.Unit) != record.Unit ||
		record.Decimals < 0 || record.Decimals > budgets.MaxAmount ||
		record.Consumed < 0 || record.Consumed > budgets.MaxAmount || record.RecordedAt <= 0 {
		return ErrBudgetUsageIntegrity
	}
	return nil
}

// Validate checks one authenticated usage query's scope and key selection.
func (query BudgetUsageQuery) Validate() error {
	if aa.ValidateServerIdentifier(query.PersonServer) != nil {
		return ErrBudgetUsageInvalidRequest
	}
	scopeCount := 0
	for _, value := range []string{query.Subject, query.Tenant, query.MissionS256} {
		if value != "" {
			scopeCount++
			if !validUsageIdentity(value) {
				return ErrBudgetUsageInvalidRequest
			}
		}
	}
	if query.MissionS256 != "" && !validRetainedThumbprint(query.MissionS256) {
		return ErrBudgetUsageInvalidRequest
	}
	if scopeCount > 1 || (scopeCount == 0 && len(query.AgentJKT) == 0) {
		return ErrBudgetUsageInvalidRequest
	}
	seen := make(map[string]struct{}, len(query.AgentJKT))
	for _, key := range query.AgentJKT {
		if !validRetainedThumbprint(key) {
			return ErrBudgetUsageInvalidRequest
		}
		if _, exists := seen[key]; exists {
			return ErrBudgetUsageInvalidRequest
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validUsageIdentity(value string) bool {
	return value != "" && strings.TrimSpace(value) == value
}

func validBudgetExecutionKey(value string) bool {
	if value == "" {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func (store *FileBudgetStore) Usage(ctx context.Context, query BudgetUsageQuery, now time.Time) (BudgetUsageSnapshot, error) {
	var snapshot BudgetUsageSnapshot
	if ctx == nil {
		return snapshot, ErrBudgetUsageStore
	}
	select {
	case <-ctx.Done():
		return snapshot, ctx.Err()
	default:
	}
	if err := query.Validate(); err != nil {
		return snapshot, err
	}
	if store == nil || store.file == nil {
		return snapshot, ErrBudgetUsageStore
	}
	now = now.UTC()
	if now.IsZero() {
		return snapshot, ErrBudgetUsageInvalidRequest
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	knownSigner := false
	for _, record := range store.usage {
		if record.PersonServer == query.PersonServer {
			knownSigner = true
			break
		}
	}
	if !knownSigner {
		return snapshot, ErrBudgetUsageUnauthorized
	}
	snapshot.AsOf = now.Unix()
	snapshot.ByKey = make(map[string]int64)
	var selected []BudgetUsageRecord
	for _, record := range store.usage {
		if record.PersonServer != query.PersonServer || !usageRecordMatchesQuery(record, query) {
			continue
		}
		if snapshot.Unit == "" {
			snapshot.Unit, snapshot.Decimals = record.Unit, record.Decimals
		} else if snapshot.Unit != record.Unit || snapshot.Decimals != record.Decimals {
			return BudgetUsageSnapshot{}, ErrBudgetUsageMixedUnits
		}
		selected = append(selected, record)
	}
	if snapshot.Unit == "" {
		for _, record := range store.usage {
			if record.PersonServer == query.PersonServer {
				snapshot.Unit, snapshot.Decimals = record.Unit, record.Decimals
				break
			}
		}
	}
	for _, record := range selected {
		if snapshot.Usage == nil {
			snapshot.Usage = &BudgetUsageCounters{}
		}
		snapshot.Usage.AllTime += record.Consumed
		if record.AgentJKT != "" && usageKeyRequested(record.AgentJKT, query.AgentJKT) {
			snapshot.ByKey[record.AgentJKT] += record.Consumed
		}
		at := time.Unix(record.RecordedAt, 0).UTC()
		if !at.Before(usageDayStart(now)) {
			snapshot.Usage.Day += record.Consumed
		}
		if !at.Before(usageWeekStart(now)) {
			snapshot.Usage.Week += record.Consumed
		}
		if !at.Before(time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)) {
			snapshot.Usage.Month += record.Consumed
		}
		if !at.Before(time.Date(now.Year(), 1, 1, 0, 0, 0, 0, time.UTC)) {
			snapshot.Usage.Year += record.Consumed
		}
	}
	return snapshot, nil
}

func cloneBudgetUsage(records map[string]BudgetUsageRecord) map[string]BudgetUsageRecord {
	cloned := make(map[string]BudgetUsageRecord, len(records))
	for key, record := range records {
		cloned[key] = record
	}
	return cloned
}

func usageRecordMatchesQuery(record BudgetUsageRecord, query BudgetUsageQuery) bool {
	switch {
	case query.Subject != "":
		return record.Subject == query.Subject
	case query.Tenant != "":
		return record.Tenant == query.Tenant
	case query.MissionS256 != "":
		return record.MissionS256 == query.MissionS256
	default:
		for _, key := range query.AgentJKT {
			if record.AgentJKT == key {
				return true
			}
		}
		return false
	}
}

func usageKeyRequested(recordKey string, requested []string) bool {
	if len(requested) == 0 {
		return true
	}
	for _, key := range requested {
		if key == recordKey {
			return true
		}
	}
	return false
}

func usageDayStart(now time.Time) time.Time {
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
}

func usageWeekStart(now time.Time) time.Time {
	day := usageDayStart(now)
	daysSinceMonday := (int(day.Weekday()) + 6) % 7
	return day.AddDate(0, 0, -daysSinceMonday)
}

func budgetUsageEndpointPath(identifier, endpoint string) (string, error) {
	resourceURL, err := url.Parse(identifier)
	if err != nil {
		return "", err
	}
	usageURL, err := url.Parse(endpoint)
	if err != nil || usageURL.Scheme != "https" || usageURL.Host != resourceURL.Host || usageURL.User != nil || usageURL.RawQuery != "" || usageURL.Fragment != "" || usageURL.Path == "" || usageURL.Path == "/" {
		return "", fmt.Errorf("usage endpoint must be an HTTPS URL on the resource origin with a literal path")
	}
	return usageURL.EscapedPath(), nil
}

func validateBudgetUsagePath(path string) error {
	for _, prefix := range []string{
		"/authorize", "/revoke", "/jwks", "/.well-known/", "/pending/", "/deferred/", "/interaction/", "/r3/",
	} {
		if path == prefix || strings.HasPrefix(path, prefix) {
			return errors.New("usage endpoint path conflicts with a reserved resource route")
		}
	}
	return nil
}

func (resource *Resource) handleBudgetUsage(response http.ResponseWriter, request *http.Request) {
	if request.URL.RawQuery != "" {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("usage endpoint does not accept query parameters"))
		return
	}
	body, err := readBoundedRequestBody(request)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	verified, err := aa.VerifyRequest(
		request.Context(), request, resource.keyResolver, resource.clock,
		aa.VerifyRequestOptions{
			RequiredComponents:       []string{"content-type", "content-digest"},
			AllowedSignatureKeyTypes: []signaturekey.Scheme{signaturekey.SchemeJWKSURI},
		},
	)
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	var query BudgetUsageQuery
	if err := decodeJSONBytes(bytes.NewReader(body), &query); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	query.PersonServer = verified.Signer
	if err := query.Validate(); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	snapshot, err := resource.budgetUsageStore.Usage(request.Context(), query, resource.clock.Now().UTC())
	if errors.Is(err, ErrBudgetUsageUnauthorized) {
		writeProblem(response, http.StatusForbidden, "usage_denied", errors.New("person server has no observed Budget authorization"))
		return
	}
	if err != nil {
		writeProblem(response, http.StatusServiceUnavailable, "usage_unavailable", err)
		return
	}
	payload := map[string]any{
		"as_of":    snapshot.AsOf,
		"aud":      verified.Signer,
		"unit":     snapshot.Unit,
		"decimals": snapshot.Decimals,
	}
	if query.Subject != "" {
		payload["sub"] = query.Subject
	}
	if query.Tenant != "" {
		payload["tenant"] = query.Tenant
	}
	if query.MissionS256 != "" {
		payload["mission_s256"] = query.MissionS256
	}
	if snapshot.Usage != nil {
		payload["usage"] = snapshot.Usage
	}
	if query.AgentJKT != nil {
		payload["jkts"] = snapshot.ByKey
	}
	resource.writeBudgetUsageJSON(response, request, http.StatusOK, payload)
}

// writeBudgetUsageJSON writes one deterministic usage representation. A
// normal configured Resource has a signing key, so its successful usage
// response carries the response-side HTTP Message Signature. A deliberately
// keyless Resource remains an unsigned reference deployment, as permitted by
// the Budget profile's recommended response signing.
func (resource *Resource) writeBudgetUsageJSON(response http.ResponseWriter, request *http.Request, status int, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "usage_unavailable", err)
		return
	}
	body = append(body, '\n')
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	headers.Set("Cache-Control", "no-store")
	if resource.hasSigningKey {
		signed := &http.Response{
			StatusCode: status,
			Header:     headers,
			Body:       io.NopCloser(bytes.NewReader(body)),
		}
		if err := signaturekey.SignResponse(signed, request, resource.signingKey, resource.identifier, aa.ResourceDiscoveryDocument, resource.clock); err != nil {
			writeProblem(response, http.StatusInternalServerError, "usage_unavailable", err)
			return
		}
		body, err = io.ReadAll(signed.Body)
		if closeErr := signed.Body.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "usage_unavailable", err)
			return
		}
		headers = signed.Header
	}
	for name, values := range headers {
		for _, value := range values {
			response.Header().Add(name, value)
		}
	}
	response.WriteHeader(status)
	_, _ = response.Write(body)
}
