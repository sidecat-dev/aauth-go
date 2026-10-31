package resource

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func (server *Server) serveUsage(response http.ResponseWriter, request *http.Request) {
	prepared, err := signaturekey.PrepareRequest(request, server.clock, signaturekey.VerifyOptions{
		RequiredComponents: authorizationSignatureComponents(server.additionalSignatureComponents),
		AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeJWKSURI},
		MaxBodyBytes:       server.maxSignedBodyBytes,
	})
	if err != nil {
		writeProblem(response, http.StatusUnauthorized, "invalid_request", err)
		return
	}
	caller, document, _, ok := prepared.Credential().JWKSURI()
	if !ok || (document != aauth.PersonDiscoveryDocument && document != aauth.AccessDiscoveryDocument) {
		writeProblem(response, http.StatusUnauthorized, "invalid_request", errors.New("usage caller must be a Person Server or an Access Server"))
		return
	}
	proof, err := prepared.VerifyJWKSURI(request.Context(), server.keyResolver)
	if err != nil {
		writeProblem(response, http.StatusUnauthorized, "invalid_request", err)
		return
	}
	if proof.Signer() != caller {
		writeProblem(response, http.StatusUnauthorized, "invalid_request", errors.New("usage caller proof signer does not match its issuer"))
		return
	}
	store, ok := server.budget.store.(BudgetUsageStore)
	if !ok {
		writeProblem(response, http.StatusNotFound, "invalid_request", errors.New("usage endpoint is not configured"))
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maximumAuthorizationRequestBytes+1))
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if len(body) > maximumAuthorizationRequestBytes {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("usage request body is too large"))
		return
	}
	query, err := budgets.ParseUsageRequest(body)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if err := validateUsageCaller(document, query); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	asOf := server.clock.Now().UTC()
	result, err := store.QueryUsage(request.Context(), BudgetUsageQuery{
		Caller:       BudgetUsageCaller{Identifier: caller, Document: document},
		AsOf:         asOf,
		Subject:      query.Subject,
		Tenant:       query.Tenant,
		MissionS256:  query.MissionS256,
		PersonServer: query.PersonServer,
		JKTs:         append([]string(nil), query.JKTs...),
	})
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if !result.AsOf.IsZero() {
		asOf = result.AsOf.UTC()
	}
	payload, err := usageResponseBody(server, query, caller, asOf.Unix(), result)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	server.writeSignedUsage(response, request, payload)
}

// writeSignedUsage sends a usage answer signed under the Resource's
// jwks_uri key, as Budgets The Signed Response recommends: the signature
// covers @status, content-type and content-digest, and binds the response to
// the request with @authority and @path under req. A Resource that publishes
// no key answers unsigned.
func (server *Server) writeSignedUsage(response http.ResponseWriter, request *http.Request, payload usageResponseBodyValue) {
	body, err := json.Marshal(payload)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	body = append(body, '\n')
	header := http.Header{}
	header.Set("Content-Type", "application/json")
	header.Set("Cache-Control", "no-store")
	if server.signingKey.ID() != "" {
		credential, err := signaturekey.NewJWKSURICredential(server.issuer, aauth.ResourceDiscoveryDocument, server.signingKey.ID())
		if err == nil {
			err = signaturekey.SignResponse(
				header, http.StatusOK, body, request, server.signingKey, credential, server.clock,
				budgets.UsageResponseSignOptions(),
			)
		}
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", fmt.Errorf("sign usage response: %w", err))
			return
		}
	}
	for name, values := range header {
		response.Header()[name] = values
	}
	response.Header().Set("Content-Length", strconv.Itoa(len(body)))
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(body)
}

func validateUsageCaller(document string, request budgets.UsageRequest) error {
	switch document {
	case aauth.PersonDiscoveryDocument:
		if request.PersonServer != "" {
			return errors.New("a Person Server usage request must omit ps")
		}
	case aauth.AccessDiscoveryDocument:
		if request.HasScope() && request.PersonServer == "" {
			return errors.New("an Access Server usage request requires ps when it carries a scope key")
		}
		if !request.HasScope() && request.PersonServer != "" {
			return errors.New("an Access Server usage request carries ps without a scope key")
		}
	default:
		return errors.New("usage caller must be a Person Server or an Access Server")
	}
	return nil
}

type usageResponseBodyValue struct {
	AsOf        int64             `json:"as_of"`
	Audience    string            `json:"aud"`
	Unit        string            `json:"unit"`
	Decimals    int64             `json:"decimals"`
	Subject     string            `json:"sub,omitempty"`
	Tenant      string            `json:"tenant,omitempty"`
	MissionS256 string            `json:"mission_s256,omitempty"`
	Usage       *usageObjectBody  `json:"usage,omitempty"`
	JKTs        *map[string]int64 `json:"jkts,omitempty"`
}

type usageObjectBody struct {
	Day     *int64 `json:"day,omitempty"`
	Week    *int64 `json:"week,omitempty"`
	Month   *int64 `json:"month,omitempty"`
	Year    *int64 `json:"year,omitempty"`
	AllTime int64  `json:"all_time"`
}

func usageResponseBody(server *Server, request budgets.UsageRequest, caller string, asOf int64, result BudgetUsageResult) (usageResponseBodyValue, error) {
	unit := result.Unit
	if !result.HasUnit {
		if server.budget == nil || len(server.budget.units) == 0 {
			return usageResponseBodyValue{}, errors.New("resource usage response has no declared unit")
		}
		unit = server.budget.units[0].Unit()
	}
	body := usageResponseBodyValue{
		AsOf: asOf, Audience: caller, Unit: unit.Name(), Decimals: unit.Decimals(),
		Subject: request.Subject, Tenant: request.Tenant, MissionS256: request.MissionS256,
	}
	if request.HasScope() && result.ScopeRecognized && result.AllTimeOK && result.AllTime > 0 {
		usage := &usageObjectBody{AllTime: result.AllTime}
		if result.DayOK {
			usage.Day = usageCounter(result.Day)
		}
		if result.WeekOK {
			usage.Week = usageCounter(result.Week)
		}
		if result.MonthOK {
			usage.Month = usageCounter(result.Month)
		}
		if result.YearOK {
			usage.Year = usageCounter(result.Year)
		}
		body.Usage = usage
	}
	if len(request.JKTs) > 0 {
		jkts := result.JKTs
		if jkts == nil {
			jkts = map[string]int64{}
		}
		body.JKTs = &jkts
	}
	return body, nil
}

func usageCounter(amount int64) *int64 {
	copied := amount
	return &copied
}
