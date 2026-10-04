package resource

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestMCPR3PerCallClassOperationCommitsProposalAndRetryBeforeChallenge(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 13, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := testSigningKey(t, "resource-key", 141)
	personKey := testSigningKey(t, "person-key", 142)
	accessKey := testSigningKey(t, "access-key", 143)
	agentKey := testSigningKey(t, "agent-key", 144)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:       personKey.PublicJWK(),
		{Issuer: resourceIssuer, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
		{Issuer: accessIssuer, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:       accessKey.PublicJWK(),
	}
	documents := &r3TestDocumentStore{}
	proposals := &r3ProposalTestStore{}
	retries := &r3RetryTestStore{}
	ids := []string{
		"class-resource-token", "proposal-resource-token", "proposal-resource-token-2",
		"proposal-resource-token-3", "proposal-resource-token-4", "proposal-resource-token-5",
	}
	account := "work-account"
	missionS256 := strings.Repeat("M", 43)
	expectedPrincipalScopes := []string{"records.write"}
	var applicationCalls atomic.Int32
	var blockExecution chan struct{}
	var executionEntered chan struct{}
	var describeCalls atomic.Int32
	var presentCalls atomic.Int32

	config := validConfigWithKey(resourceKey, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		sequence := applicationCalls.Add(1)
		principal, ok := AuthPrincipalFromContext(request.Context())
		if !ok || principal.Account == nil || *principal.Account != account ||
			!reflect.DeepEqual(principal.Scope, expectedPrincipalScopes) {
			t.Fatalf("per-call application principal = %#v, present=%t", principal, ok)
		}
		if blockExecution != nil {
			executionEntered <- struct{}{}
			<-blockExecution
		}
		writeJSON(response, http.StatusOK, struct {
			Sequence int32 `json:"sequence"`
		}{Sequence: sequence})
	}))
	config.Clock = clock
	config.KeyResolver = resolver
	config.AdditionalSignatureComponents = nil
	config.ScopeDescriptions = map[string]string{
		"records.write": "Write records",
		"records.audit": "Audit records",
		"records.admin": "Administer records",
	}
	config.MaxRetainedRequestBodyBytes = 64 << 10
	config.MaxRetainedResponseBodyBytes = 64 << 10
	config.MaxRetainedHeaderBytes = 16 << 10
	config.NewID = func() string {
		id := ids[0]
		ids = ids[1:]
		return id
	}
	config.RequiredScopes = func(*http.Request) []string { return []string{"records.write"} }
	config.ValidateAccount = func(_ context.Context, identity PersonIdentity, got string) error {
		if identity != (PersonIdentity{Issuer: personIssuer, Subject: "person-1"}) || got != account {
			return errors.New("unexpected account")
		}
		return nil
	}
	config.R3 = newResourceMCPConfig(t, documents, []string{"records.delete"}, func(*http.Request) (string, bool, error) {
		return "records.delete", true, nil
	})
	config.R3.HTTP.PresentParameters = func(request *http.Request, operation r3.Operation) (map[string]r3.PresentedParameter, error) {
		presentCalls.Add(1)
		identifier := strings.TrimPrefix(request.URL.Path, "/records/")
		if identifier == request.URL.Path || identifier == "" || resourceMCPTool(t, operation) != "records.delete" {
			return nil, errors.New("unexpected MCP R3 presented-call input")
		}
		encodedIdentifier, _ := json.Marshal("record-" + identifier)
		presented, err := r3.NewPresentedInlineParameter(encodedIdentifier)
		if err != nil {
			return nil, err
		}
		return map[string]r3.PresentedParameter{"id": presented}, nil
	}
	registry := config.R3.Registry
	config.R3.PerCall = &R3PerCallConfig{
		Proposals: proposals,
		Retries:   retries,
		DescribeCall: func(_ context.Context, invocation r3.Invocation, account *string) (R3CallDescription, error) {
			describeCalls.Add(1)
			tool := resourceMCPTool(t, invocation.Operation())
			presented, ok := invocation.PresentedParameters()["id"]
			if !ok {
				return R3CallDescription{}, errors.New("missing invocation id")
			}
			encodedIdentifier, ok := presented.InlineJSON()
			if !ok {
				return R3CallDescription{}, errors.New("invocation id is not inline JSON")
			}
			var recordID string
			if err := json.Unmarshal(encodedIdentifier, &recordID); err != nil {
				return R3CallDescription{}, err
			}
			identifier := strings.TrimPrefix(recordID, "record-")
			if identifier == recordID || identifier == "" || tool != "records.delete" ||
				account == nil || *account != "work-account" {
				t.Fatalf("proposal input = %s, %s, %#v", recordID, tool, account)
			}
			inline, err := r3.NewInlineParameter(encodedIdentifier)
			if err != nil {
				return R3CallDescription{}, err
			}
			parameters, err := r3.NewParameters(map[string]r3.Parameter{"id": inline})
			if err != nil {
				return R3CallDescription{}, err
			}
			display, err := r3.NewDisplay("Delete record "+identifier, "", "Record "+identifier, "Deletion cannot be undone")
			if err != nil {
				return R3CallDescription{}, err
			}
			proposalDisplay, err := r3.NewProposalDisplay(display, "## Action\nDelete record "+identifier)
			if err != nil {
				return R3CallDescription{}, err
			}
			return R3CallDescription{
				Parameters: parameters,
				Display:    &proposalDisplay,
			}, nil
		},
	}
	server, err := NewFederatedAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}

	personToken, err := aauth.MintPersonToken(personKey, aauth.PersonTokenClaims{
		Issuer: personIssuer, DWK: aauth.PersonDiscoveryDocument,
		Audience: resourceIssuer, Subject: "person-1", JTI: "person-token-1",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
		MissionS256: missionS256, Tenant: "tenant-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	authorize := signedRequest(t, clock, agentKey, personToken, http.MethodPost, resourceIssuer+"/authorize", `{"scope":"records.write records.audit","account":"work-account","r3_operations":{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.delete"}]}}`)
	authorizeResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(authorizeResponse, authorize)
	if authorizeResponse.Code != http.StatusOK {
		t.Fatalf("class authorization = %d %s", authorizeResponse.Code, authorizeResponse.Body.String())
	}
	var authorizationOutput struct {
		ResourceToken string `json:"resource_token"`
	}
	if err := json.Unmarshal(authorizeResponse.Body.Bytes(), &authorizationOutput); err != nil {
		t.Fatal(err)
	}
	classResourceClaims, classReference, err := r3.VerifyResourceToken(context.Background(), authorizationOutput.ResourceToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	classRecord, err := documents.Load(context.Background(), classReference.URI())
	if err != nil {
		t.Fatal(err)
	}
	if classRecord.ClassContext.ExactResourceToken != authorizationOutput.ResourceToken {
		t.Fatal("class context did not retain the exact Resource token")
	}
	classDocument, err := registry.ParseReferencedDocument(classReference, classRecord.ExactJSON)
	if err != nil {
		t.Fatal(err)
	}
	empty, _ := r3.NewGrantedOperations(mcp.Vocabulary())
	deleteOperation := newResourceMCPOperation(t, "records.delete")
	perCall, _ := r3.NewGrantedOperations(mcp.Vocabulary(), deleteOperation)
	classAuthorization, err := r3.NewAuthorization(empty, perCall, classDocument)
	if err != nil {
		t.Fatal(err)
	}
	classAuthToken, err := r3.MintAuthToken(registry, accessKey, aauth.AuthTokenClaims{
		Issuer: accessIssuer, DWK: aauth.AccessDiscoveryDocument,
		Audience: resourceIssuer, JTI: "class-auth-token",
		PersonServer: personIssuer, Subject: "person-1",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
		Scope: "records.write records.audit", MissionS256: missionS256,
		Tenant: classRecord.ClassContext.ResourceToken.Tenant, Account: &account,
	}, classReference, classRecord.ExactJSON, classAuthorization)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(6 * time.Minute)
	remainingIDs := append([]string(nil), ids...)
	ids = append([]string{""}, ids...)
	emptyIDCall := signedRequest(t, clock, agentKey, classAuthToken, http.MethodDelete, resourceIssuer+"/records/7", "")
	emptyIDResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(emptyIDResponse, emptyIDCall)
	if emptyIDResponse.Code != http.StatusInternalServerError ||
		emptyIDResponse.Header().Get("AAuth-Requirement") != "" || emptyIDResponse.Header().Get("Location") != "" ||
		proposals.count() != 0 || retries.count() != 0 || applicationCalls.Load() != 0 {
		t.Fatalf(
			"empty proposal id = %d headers=%v stores=%d/%d application=%d",
			emptyIDResponse.Code, emptyIDResponse.Header(), proposals.count(), retries.count(), applicationCalls.Load(),
		)
	}
	ids = remainingIDs
	presentCalls.Store(0)
	describeCalls.Store(0)
	for _, issuedAt := range []int64{classResourceClaims.IssuedAt - 1, classResourceClaims.ExpiresAt} {
		outsideLineage, err := r3.MintAuthToken(registry, accessKey, aauth.AuthTokenClaims{
			Issuer: accessIssuer, DWK: aauth.AccessDiscoveryDocument,
			Audience: resourceIssuer, JTI: "outside-class-lineage",
			PersonServer: personIssuer, Subject: "person-1",
			Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
			IssuedAt:     issuedAt, ExpiresAt: issuedAt + int64(time.Hour/time.Second),
			Scope: "records.write", MissionS256: missionS256,
			Tenant: classResourceClaims.Tenant, Account: &account,
		}, classReference, classRecord.ExactJSON, classAuthorization)
		if err != nil {
			t.Fatal(err)
		}
		outsideCall := signedRequest(t, clock, agentKey, outsideLineage, http.MethodDelete, resourceIssuer+"/records/7", "")
		outsideResponse := httptest.NewRecorder()
		server.Handler().ServeHTTP(outsideResponse, outsideCall)
		if outsideResponse.Code != http.StatusForbidden || presentCalls.Load() != 0 || describeCalls.Load() != 0 ||
			proposals.count() != 0 || retries.count() != 0 {
			t.Fatalf(
				"class Auth issued at %d = %d %s, adapters=%d/%d stores=%d/%d",
				issuedAt, outsideResponse.Code, outsideResponse.Body.String(), presentCalls.Load(), describeCalls.Load(), proposals.count(), retries.count(),
			)
		}
	}
	documents.mutate(classReference.URI(), func(record *R3DocumentRecord) {
		record.ClassContext.ResourceToken.PresentedJTI = "changed-person-token"
	})
	changedClassContextCall := signedRequest(t, clock, agentKey, classAuthToken, http.MethodDelete, resourceIssuer+"/records/7", "")
	changedClassContext := httptest.NewRecorder()
	server.Handler().ServeHTTP(changedClassContext, changedClassContextCall)
	if changedClassContext.Code != http.StatusInternalServerError || presentCalls.Load() != 0 || describeCalls.Load() != 0 ||
		proposals.count() != 0 || retries.count() != 0 {
		t.Fatalf(
			"changed retained class context = %d %s, adapters=%d/%d stores=%d/%d",
			changedClassContext.Code, changedClassContext.Body.String(), presentCalls.Load(), describeCalls.Load(), proposals.count(), retries.count(),
		)
	}
	documents.mutate(classReference.URI(), func(record *R3DocumentRecord) { *record = cloneR3TestRecord(classRecord) })

	commitFailureProposals := &r3ProposalTestStore{commitErr: errors.New("proposal commit failed")}
	config.R3.PerCall.Proposals = commitFailureProposals
	server, err = NewFederatedAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	ids = append([]string{"proposal-commit-failure"}, ids...)
	commitFailureRequest := signedRequest(t, clock, agentKey, classAuthToken, http.MethodDelete, resourceIssuer+"/records/7", "")
	commitFailureResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(commitFailureResponse, commitFailureRequest)
	if commitFailureResponse.Code != http.StatusInternalServerError ||
		commitFailureResponse.Header().Get("AAuth-Requirement") != "" || commitFailureResponse.Header().Get("Location") != "" ||
		commitFailureProposals.count() != 0 || retries.count() != 0 || applicationCalls.Load() != 0 {
		t.Fatalf(
			"proposal commit failure = %d headers=%v stores=%d/%d application=%d",
			commitFailureResponse.Code, commitFailureResponse.Header(), commitFailureProposals.count(), retries.count(), applicationCalls.Load(),
		)
	}

	prepareFailureRetries := &r3RetryTestStore{prepareErr: errors.New("retry prepare failed")}
	config.R3.PerCall.Proposals = proposals
	config.R3.PerCall.Retries = prepareFailureRetries
	server, err = NewFederatedAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	ids = append([]string{"retry-prepare-failure"}, ids...)
	prepareFailureRequest := signedRequest(t, clock, agentKey, classAuthToken, http.MethodDelete, resourceIssuer+"/records/7", "")
	prepareFailureResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(prepareFailureResponse, prepareFailureRequest)
	if prepareFailureResponse.Code != http.StatusInternalServerError ||
		prepareFailureResponse.Header().Get("AAuth-Requirement") != "" || prepareFailureResponse.Header().Get("Location") != "" ||
		proposals.count() != 1 || prepareFailureRetries.count() != 0 || applicationCalls.Load() != 0 {
		t.Fatalf(
			"retry prepare failure = %d headers=%v stores=%d/%d application=%d",
			prepareFailureResponse.Code, prepareFailureResponse.Header(), proposals.count(), prepareFailureRetries.count(), applicationCalls.Load(),
		)
	}
	proposals = &r3ProposalTestStore{}
	config.R3.PerCall.Proposals = proposals
	config.R3.PerCall.Retries = retries
	server, err = NewFederatedAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	presentCalls.Store(0)
	describeCalls.Store(0)
	expandedClassAuthToken, err := r3.MintAuthToken(registry, accessKey, aauth.AuthTokenClaims{
		Issuer: accessIssuer, DWK: aauth.AccessDiscoveryDocument,
		Audience: resourceIssuer, JTI: "expanded-class-auth-token",
		PersonServer: personIssuer, Subject: "person-1",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Add(-6 * time.Minute).Unix(), ExpiresAt: now.Add(54 * time.Minute).Unix(),
		Scope: "records.write records.admin", MissionS256: missionS256,
		Tenant: classRecord.ClassContext.ResourceToken.Tenant, Account: &account,
	}, classReference, classRecord.ExactJSON, classAuthorization)
	if err != nil {
		t.Fatal(err)
	}
	expandedClassCall := signedRequest(t, clock, agentKey, expandedClassAuthToken, http.MethodDelete, resourceIssuer+"/records/7", "")
	expandedClassResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(expandedClassResponse, expandedClassCall)
	if expandedClassResponse.Code != http.StatusForbidden ||
		expandedClassResponse.Header().Get("AAuth-Requirement") != "" ||
		describeCalls.Load() != 0 || presentCalls.Load() != 0 || proposals.count() != 0 || retries.count() != 0 {
		t.Fatalf(
			"expanded class scope = %d headers=%v describe/present=%d/%d stores=%d/%d",
			expandedClassResponse.Code, expandedClassResponse.Header(), describeCalls.Load(), presentCalls.Load(), proposals.count(), retries.count(),
		)
	}

	call := signedRequest(t, clock, agentKey, classAuthToken, http.MethodDelete, resourceIssuer+"/records/7", "")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, call)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("per-call challenge = %d %s", response.Code, response.Body.String())
	}
	if applicationCalls.Load() != 0 || describeCalls.Load() != 1 || presentCalls.Load() != 1 {
		t.Fatalf("application/describe/present calls = %d/%d/%d; header=%v body=%s", applicationCalls.Load(), describeCalls.Load(), presentCalls.Load(), response.Header(), response.Body.String())
	}
	requirement, err := aauth.ParseAuthTokenRequirement(response.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	proposalClaims, proposalReference, err := r3.VerifyResourceToken(context.Background(), requirement.ResourceToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if proposalClaims.PresentedJTI != "class-auth-token" || proposalClaims.JTI != "proposal-resource-token" {
		t.Fatalf("proposal Resource claims = %#v", proposalClaims)
	}
	proposalRecord, err := proposals.Load(context.Background(), proposalReference.URI())
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := registry.ParseReferencedProposal(proposalReference, proposalRecord.ExactJSON)
	if err != nil {
		t.Fatal(err)
	}
	if !equalResourceR3Operations(t, proposal.Operation(), deleteOperation) || proposalRecord.ClassReference != classReference {
		t.Fatalf("proposal record = %#v, proposal = %#v", proposalRecord, proposal)
	}
	retryRecord, err := retries.Load(context.Background(), proposalReference)
	if err != nil {
		t.Fatal(err)
	}
	if retryRecord.Reference != proposalReference || retryRecord.ClassReference != classReference ||
		retryRecord.ResourceToken != requirement.ResourceToken ||
		!reflect.DeepEqual(retryRecord.ExactProposal, proposalRecord.ExactJSON) ||
		!retryRecord.CompletionUntil.Equal(retryRecord.ExpiresAt.Add(aauth.MaximumAuthTokenLifetime)) {
		t.Fatalf("retry record = %#v", retryRecord)
	}
	ids = append([]string{proposalClaims.JTI}, ids...)
	duplicateIDRequest := signedRequest(t, clock, agentKey, classAuthToken, http.MethodDelete, resourceIssuer+"/records/7", "")
	duplicateIDResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(duplicateIDResponse, duplicateIDRequest)
	if duplicateIDResponse.Code != http.StatusInternalServerError ||
		duplicateIDResponse.Header().Get("AAuth-Requirement") != "" ||
		proposals.count() != 1 || retries.count() != 1 || applicationCalls.Load() != 0 {
		t.Fatalf(
			"duplicate proposal id = %d headers=%v stores=%d/%d application=%d",
			duplicateIDResponse.Code, duplicateIDResponse.Header(), proposals.count(), retries.count(), applicationCalls.Load(),
		)
	}
	secondChallengeRequest := signedRequest(t, clock, agentKey, classAuthToken, http.MethodDelete, resourceIssuer+"/records/7", "")
	secondChallenge := httptest.NewRecorder()
	server.Handler().ServeHTTP(secondChallenge, secondChallengeRequest)
	if secondChallenge.Code != http.StatusUnauthorized {
		t.Fatalf("second identical challenge = %d %s", secondChallenge.Code, secondChallenge.Body.String())
	}
	secondRequirement, err := aauth.ParseAuthTokenRequirement(secondChallenge.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	secondClaims, secondReference, err := r3.VerifyResourceToken(context.Background(), secondRequirement.ResourceToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if secondReference.URI() == proposalReference.URI() || secondReference.Digest() != proposalReference.Digest() ||
		secondClaims.JTI != "proposal-resource-token-2" {
		t.Fatalf("identical proposal references = %#v and %#v; second claims=%#v", proposalReference, secondReference, secondClaims)
	}
	secondProposalRecord, err := proposals.Load(context.Background(), secondReference.URI())
	if err != nil {
		t.Fatal(err)
	}
	if proposals.count() != 2 || retries.count() != 2 {
		t.Fatalf("proposal/retry records = %d/%d", proposals.count(), retries.count())
	}
	server, err = NewFederatedAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}

	perCallAuthToken, err := r3.MintPerCallAuthToken(registry, accessKey, aauth.AuthTokenClaims{
		Issuer: accessIssuer, DWK: aauth.AccessDiscoveryDocument,
		Audience: resourceIssuer, JTI: "per-call-auth-token",
		PersonServer: personIssuer, Subject: "person-1",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(30 * time.Minute).Unix(),
		Scope: "records.write", MissionS256: missionS256,
		Tenant: classRecord.ClassContext.ResourceToken.Tenant, Account: &account,
	}, proposalReference, proposalRecord.ExactJSON)
	if err != nil {
		t.Fatal(err)
	}
	retryCall := func(compact string) *httptest.ResponseRecorder {
		request := signedRequest(t, clock, agentKey, compact, http.MethodDelete, resourceIssuer+"/records/7", "")
		result := httptest.NewRecorder()
		server.Handler().ServeHTTP(result, request)
		return result
	}
	proposalURIJSON, _ := json.Marshal(proposalReference.URI())
	proposalDigestJSON, _ := json.Marshal(proposalReference.Digest())
	proposalGrant, _ := r3.NewGrantedOperations(mcp.Vocabulary(), deleteOperation)
	proposalGrantJSON, _ := json.Marshal(proposalGrant)
	emptyPerCall, _ := r3.NewGrantedOperations(mcp.Vocabulary())
	emptyPerCallJSON, _ := json.Marshal(emptyPerCall)
	explicitEmptyPerCallToken, err := aauth.MintAuthTokenCore(accessKey, aauth.AuthTokenClaims{
		Issuer: accessIssuer, DWK: aauth.AccessDiscoveryDocument,
		Audience: resourceIssuer, JTI: "explicit-empty-per-call-auth-token",
		PersonServer: personIssuer, Subject: "person-1",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(30 * time.Minute).Unix(),
		Scope: "records.write", MissionS256: missionS256,
		Tenant: classResourceClaims.Tenant, Account: &account,
		AdditionalClaims: map[string]json.RawMessage{
			"r3_uri": proposalURIJSON, "r3_s256": proposalDigestJSON,
			"r3_granted": proposalGrantJSON, "r3_per_call": emptyPerCallJSON,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	explicitEmptyPerCall := retryCall(explicitEmptyPerCallToken)
	if explicitEmptyPerCall.Code != http.StatusForbidden || applicationCalls.Load() != 0 {
		t.Fatalf(
			"explicit empty r3_per_call completion = %d %s, application calls=%d",
			explicitEmptyPerCall.Code, explicitEmptyPerCall.Body.String(), applicationCalls.Load(),
		)
	}
	if claims, _ := retries.observation(proposalReference); claims != 0 {
		t.Fatalf("explicit empty r3_per_call crossed Claim %d times", claims)
	}
	// A proposal token that names no presented token can no longer be minted,
	// so that refusal is proved at the mint rather than at the retained record.
	// A different nonempty presented_jti is not refused on retry: the class
	// record cannot hold the class Auth token's jti.
	missingPresentedClaims := proposalClaims
	missingPresentedClaims.PresentedJTI = ""
	if _, _, err := r3.MintProposalResourceToken(
		registry, resourceKey, missingPresentedClaims, proposalReference.URI(), proposalRecord.ExactJSON,
	); err == nil {
		t.Fatal("proposal token without presented_jti was minted")
	}
	for _, scenario := range []struct {
		name   string
		change func(*aauth.ResourceTokenClaims)
	}{
		{name: "proposal token id", change: func(claims *aauth.ResourceTokenClaims) { claims.JTI = "other-proposal-token" }},
		{name: "issued at", change: func(claims *aauth.ResourceTokenClaims) { claims.IssuedAt++ }},
		{name: "expires at", change: func(claims *aauth.ResourceTokenClaims) { claims.ExpiresAt++ }},
		{name: "agent key", change: func(claims *aauth.ResourceTokenClaims) { claims.AgentJKT = strings.Repeat("A", 43) }},
		{name: "requested scope", change: func(claims *aauth.ResourceTokenClaims) { claims.Scope = "records.write records.admin" }},
	} {
		changedClaims := proposalClaims
		scenario.change(&changedClaims)
		changedResourceToken, changedReference, err := r3.MintProposalResourceToken(
			registry, resourceKey, changedClaims, proposalReference.URI(), proposalRecord.ExactJSON,
		)
		if err != nil {
			t.Fatalf("mint changed %s proposal token: %v", scenario.name, err)
		}
		if changedReference != proposalReference {
			t.Fatalf("changed %s proposal reference = %#v", scenario.name, changedReference)
		}
		retries.loadResult = func(invocation R3RetryInvocation) R3RetryInvocation {
			invocation.ResourceToken = changedResourceToken
			return invocation
		}
		changed := retryCall(perCallAuthToken)
		retries.loadResult = nil
		if changed.Code != http.StatusInternalServerError || applicationCalls.Load() != 0 {
			t.Fatalf(
				"changed retained %s = %d %s, application calls=%d",
				scenario.name, changed.Code, changed.Body.String(), applicationCalls.Load(),
			)
		}
	}
	retries.loadResult = func(invocation R3RetryInvocation) R3RetryInvocation {
		invocation.ExactProposal = []byte(`{"operation":{"name":"changed"}}`)
		return invocation
	}
	changedProposal := retryCall(perCallAuthToken)
	retries.loadResult = nil
	if changedProposal.Code != http.StatusInternalServerError || applicationCalls.Load() != 0 {
		t.Fatalf(
			"changed retained proposal = %d %s, application calls=%d",
			changedProposal.Code, changedProposal.Body.String(), applicationCalls.Load(),
		)
	}
	expandedScopeToken, err := r3.MintPerCallAuthToken(registry, accessKey, aauth.AuthTokenClaims{
		Issuer: accessIssuer, DWK: aauth.AccessDiscoveryDocument,
		Audience: resourceIssuer, JTI: "expanded-scope-auth-token",
		PersonServer: personIssuer, Subject: "person-1",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(30 * time.Minute).Unix(),
		Scope: "records.write records.admin", MissionS256: missionS256,
		Tenant: classRecord.ClassContext.ResourceToken.Tenant, Account: &account,
	}, proposalReference, proposalRecord.ExactJSON)
	if err != nil {
		t.Fatal(err)
	}
	expandedScope := retryCall(expandedScopeToken)
	if expandedScope.Code != http.StatusForbidden || applicationCalls.Load() != 0 {
		t.Fatalf("expanded 401 scope = %d %s, application calls=%d", expandedScope.Code, expandedScope.Body.String(), applicationCalls.Load())
	}
	for _, execution := range []HeldExecution{
		{InvocationID: "other-proposal", Fence: "foreign-fence"},
		{InvocationID: proposalReference.URI(), Fence: ""},
	} {
		claim := NewHeldExecution(execution)
		retries.claimResult = &claim
		invalidClaim := retryCall(perCallAuthToken)
		retries.claimResult = nil
		if invalidClaim.Code != http.StatusInternalServerError || applicationCalls.Load() != 0 {
			t.Fatalf(
				"invalid retry execution claim %#v = %d %s, application calls=%d",
				execution, invalidClaim.Code, invalidClaim.Body.String(), applicationCalls.Load(),
			)
		}
	}
	changedCall := signedRequest(t, clock, agentKey, perCallAuthToken, http.MethodDelete, resourceIssuer+"/records/8", "")
	changedResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(changedResponse, changedCall)
	if changedResponse.Code != http.StatusForbidden || applicationCalls.Load() != 0 {
		t.Fatalf("changed parameters = %d %s, application calls=%d", changedResponse.Code, changedResponse.Body.String(), applicationCalls.Load())
	}
	now = time.Unix(proposalClaims.ExpiresAt+1, 0)
	auditFetch := httptest.NewRequest(http.MethodGet, proposalReference.URI(), nil)
	if err := signaturekey.SignJWKSURIRequest(
		auditFetch, accessKey, accessIssuer, aauth.AccessDiscoveryDocument, clock,
	); err != nil {
		t.Fatal(err)
	}
	auditResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(auditResponse, auditFetch)
	if auditResponse.Code != http.StatusOK || !reflect.DeepEqual(auditResponse.Body.Bytes(), proposalRecord.ExactJSON) {
		t.Fatalf("expired proposal audit fetch = %d %s", auditResponse.Code, auditResponse.Body.String())
	}
	firstRequest := signedRequest(t, clock, agentKey, perCallAuthToken, http.MethodDelete, resourceIssuer+"/records/7", "")
	firstContext, cancelFirstTransport := context.WithCancel(firstRequest.Context())
	firstRequest = firstRequest.WithContext(firstContext)
	retries.beforeClaim = cancelFirstTransport
	retries.rejectCanceledClaim = true
	retries.beforeRetain = cancelFirstTransport
	retries.rejectCanceledRetain = true
	first := httptest.NewRecorder()
	server.Handler().ServeHTTP(first, firstRequest)
	if first.Code != http.StatusOK || first.Body.String() != "{\"sequence\":1}\n" {
		t.Fatalf("first retry = %d %s", first.Code, first.Body.String())
	}
	second := retryCall(perCallAuthToken)
	if second.Code != first.Code || second.Body.String() != first.Body.String() {
		t.Fatalf("exact replay = %d %s, want %d %s", second.Code, second.Body.String(), first.Code, first.Body.String())
	}
	competingToken, err := r3.MintPerCallAuthToken(registry, accessKey, aauth.AuthTokenClaims{
		Issuer: accessIssuer, DWK: aauth.AccessDiscoveryDocument,
		Audience: resourceIssuer, JTI: "competing-auth-token",
		PersonServer: personIssuer, Subject: "person-1",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     proposalClaims.IssuedAt, ExpiresAt: proposalClaims.IssuedAt + int64(30*time.Minute/time.Second),
		Scope: "records.write", MissionS256: missionS256,
		Tenant: classRecord.ClassContext.ResourceToken.Tenant, Account: &account,
	}, proposalReference, proposalRecord.ExactJSON)
	if err != nil {
		t.Fatal(err)
	}
	competing := retryCall(competingToken)
	if competing.Code != http.StatusForbidden {
		t.Fatalf("competing token = %d %s", competing.Code, competing.Body.String())
	}
	if applicationCalls.Load() != 1 {
		t.Fatalf("application calls after replay and competition = %d", applicationCalls.Load())
	}
	secondToken, err := r3.MintPerCallAuthToken(registry, accessKey, aauth.AuthTokenClaims{
		Issuer: accessIssuer, DWK: aauth.AccessDiscoveryDocument,
		Audience: resourceIssuer, JTI: "per-call-auth-token-2",
		PersonServer: personIssuer, Subject: "person-1",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     secondClaims.IssuedAt, ExpiresAt: secondClaims.IssuedAt + int64(30*time.Minute/time.Second),
		Scope: "records.write", MissionS256: missionS256,
		Tenant: classRecord.ClassContext.ResourceToken.Tenant, Account: &account,
	}, secondReference, secondProposalRecord.ExactJSON)
	if err != nil {
		t.Fatal(err)
	}
	blockExecution = make(chan struct{})
	executionEntered = make(chan struct{}, 1)
	firstConcurrentResult := make(chan *httptest.ResponseRecorder, 1)
	go func() { firstConcurrentResult <- retryCall(secondToken) }()
	select {
	case <-executionEntered:
	case early := <-firstConcurrentResult:
		t.Fatalf("second retry returned before application execution: %d %s", early.Code, early.Body.String())
	case <-time.After(2 * time.Second):
		t.Fatal("second retry did not reach application execution")
	}
	const concurrentDuplicates = 15
	duplicateResults := make(chan *httptest.ResponseRecorder, concurrentDuplicates)
	var duplicateWait sync.WaitGroup
	for range concurrentDuplicates {
		duplicateWait.Add(1)
		go func() {
			defer duplicateWait.Done()
			duplicateResults <- retryCall(secondToken)
		}()
	}
	duplicateWait.Wait()
	close(duplicateResults)
	for duplicate := range duplicateResults {
		if duplicate.Code != http.StatusServiceUnavailable {
			t.Fatalf("active duplicate = %d %s", duplicate.Code, duplicate.Body.String())
		}
	}
	close(blockExecution)
	secondExecution := <-firstConcurrentResult
	blockExecution = nil
	executionEntered = nil
	if secondExecution.Code != http.StatusOK || secondExecution.Body.String() != "{\"sequence\":2}\n" {
		t.Fatalf("second identical invocation = %d %s", secondExecution.Code, secondExecution.Body.String())
	}
	secondReplay := retryCall(secondToken)
	if secondReplay.Code != secondExecution.Code || secondReplay.Body.String() != secondExecution.Body.String() {
		t.Fatalf("second exact replay = %d %s", secondReplay.Code, secondReplay.Body.String())
	}
	if applicationCalls.Load() != 2 {
		t.Fatalf("two distinct identical proposals executed %d times", applicationCalls.Load())
	}
	if describeCalls.Load() != 3 {
		t.Fatalf("401 proposal descriptions = %d, want two published challenges and one rejected duplicate", describeCalls.Load())
	}

	expectedPrincipalScopes = []string{"records.write", "records.audit"}
	held := newHeldMemoryStore()
	config.HeldInvocations = held
	config.HoldAuthTokenRequest = func(*http.Request) bool { return true }
	server, err = NewFederatedAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	describesBeforeHeld := describeCalls.Load()
	presentedBeforeHeld := presentCalls.Load()
	heldCall := signedRequest(t, clock, agentKey, classAuthToken, http.MethodDelete, resourceIssuer+"/records/7", "")
	heldChallenge := httptest.NewRecorder()
	server.Handler().ServeHTTP(heldChallenge, heldCall)
	if heldChallenge.Code != http.StatusAccepted {
		t.Fatalf("held per-call challenge = %d %s", heldChallenge.Code, heldChallenge.Body.String())
	}
	heldRequirement, err := aauth.ParseAuthTokenRequirement(heldChallenge.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	heldClaims, heldReference, err := r3.VerifyResourceToken(context.Background(), heldRequirement.ResourceToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	heldProposal, err := proposals.Load(context.Background(), heldReference.URI())
	if err != nil {
		t.Fatal(err)
	}
	parsedHeldProposal, err := registry.ParseReferencedProposal(heldReference, heldProposal.ExactJSON)
	if err != nil {
		t.Fatal(err)
	}
	retainedHeld := held.loaded(t)
	if retainedHeld.R3PerCall == nil || retainedHeld.R3PerCall.Reference != heldReference ||
		retainedHeld.R3PerCall.ClassReference != classReference ||
		!equalResourceR3Operations(t, parsedHeldProposal.Operation(), deleteOperation) ||
		!reflect.DeepEqual(retainedHeld.R3PerCall.ExactProposal, heldProposal.ExactJSON) {
		t.Fatalf("retained held MCP R3 context = %#v", retainedHeld.R3PerCall)
	}
	if proposals.count() != 3 || retries.count() != 2 {
		t.Fatalf("held proposal/retry records = %d/%d", proposals.count(), retries.count())
	}
	ids = append([]string{"proposal-resource-token-3"}, ids...)
	duplicateHeldCall := signedRequest(t, clock, agentKey, classAuthToken, http.MethodDelete, resourceIssuer+"/records/7", "")
	duplicateHeldChallenge := httptest.NewRecorder()
	server.Handler().ServeHTTP(duplicateHeldChallenge, duplicateHeldCall)
	if duplicateHeldChallenge.Code != http.StatusInternalServerError ||
		duplicateHeldChallenge.Header().Get("AAuth-Requirement") != "" || duplicateHeldChallenge.Header().Get("Location") != "" ||
		proposals.count() != 3 || retries.count() != 2 || applicationCalls.Load() != 2 {
		t.Fatalf(
			"duplicate held proposal id = %d headers=%v stores=%d/%d application=%d",
			duplicateHeldChallenge.Code, duplicateHeldChallenge.Header(), proposals.count(), retries.count(), applicationCalls.Load(),
		)
	}
	server, err = NewFederatedAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	heldToken, err := r3.MintPerCallAuthToken(registry, accessKey, aauth.AuthTokenClaims{
		Issuer: accessIssuer, DWK: aauth.AccessDiscoveryDocument,
		Audience: resourceIssuer, JTI: "held-per-call-auth-token",
		PersonServer: personIssuer, Subject: "person-1",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(30 * time.Minute).Unix(),
		Scope: "records.write records.audit", MissionS256: missionS256,
		Tenant: classRecord.ClassContext.ResourceToken.Tenant, Account: &account,
	}, heldReference, heldProposal.ExactJSON)
	if err != nil {
		t.Fatal(err)
	}
	missingRequiredScopeToken, err := r3.MintPerCallAuthToken(registry, accessKey, aauth.AuthTokenClaims{
		Issuer: accessIssuer, DWK: aauth.AccessDiscoveryDocument,
		Audience: resourceIssuer, JTI: "held-missing-required-scope-auth-token",
		PersonServer: personIssuer, Subject: "person-1",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(30 * time.Minute).Unix(),
		Scope: "records.audit", MissionS256: missionS256,
		Tenant: classRecord.ClassContext.ResourceToken.Tenant, Account: &account,
	}, heldReference, heldProposal.ExactJSON)
	if err != nil {
		t.Fatal(err)
	}
	missingRequiredScopePoll := signedRequest(
		t, clock, agentKey, missingRequiredScopeToken, http.MethodGet, heldChallenge.Header().Get("Location"), "",
	)
	missingRequiredScopeResult := httptest.NewRecorder()
	server.Handler().ServeHTTP(missingRequiredScopeResult, missingRequiredScopePoll)
	if missingRequiredScopeResult.Code != http.StatusForbidden || applicationCalls.Load() != 2 {
		t.Fatalf(
			"held missing required scope = %d %s, application calls=%d",
			missingRequiredScopeResult.Code, missingRequiredScopeResult.Body.String(), applicationCalls.Load(),
		)
	}
	wrongAudienceToken, err := r3.MintPerCallAuthToken(registry, accessKey, aauth.AuthTokenClaims{
		Issuer: accessIssuer, DWK: aauth.AccessDiscoveryDocument,
		Audience: "https://other-resource.example", JTI: "held-wrong-audience-auth-token",
		PersonServer: personIssuer, Subject: "person-1",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(30 * time.Minute).Unix(),
		Scope: "records.write records.audit", MissionS256: missionS256,
		Tenant: classRecord.ClassContext.ResourceToken.Tenant, Account: &account,
	}, heldReference, heldProposal.ExactJSON)
	if err != nil {
		t.Fatal(err)
	}
	wrongAudiencePoll := signedRequest(
		t, clock, agentKey, wrongAudienceToken, http.MethodGet, heldChallenge.Header().Get("Location"), "",
	)
	wrongAudienceResult := httptest.NewRecorder()
	server.Handler().ServeHTTP(wrongAudienceResult, wrongAudiencePoll)
	if wrongAudienceResult.Code != http.StatusForbidden || applicationCalls.Load() != 2 {
		t.Fatalf(
			"held cross-resource token = %d %s, application calls=%d",
			wrongAudienceResult.Code, wrongAudienceResult.Body.String(), applicationCalls.Load(),
		)
	}
	foreignReferencePollRequest := signedRequest(
		t, clock, agentKey, secondToken, http.MethodGet, heldChallenge.Header().Get("Location"), "",
	)
	foreignReferencePoll := httptest.NewRecorder()
	server.Handler().ServeHTTP(foreignReferencePoll, foreignReferencePollRequest)
	if foreignReferencePoll.Code != http.StatusForbidden || applicationCalls.Load() != 2 {
		t.Fatalf(
			"held foreign proposal reference = %d %s, application calls=%d",
			foreignReferencePoll.Code, foreignReferencePoll.Body.String(), applicationCalls.Load(),
		)
	}
	for _, scenario := range []struct {
		name   string
		change func(*HeldInvocation)
	}{
		{name: "changed stored reference", change: func(invocation *HeldInvocation) {
			invocation.R3PerCall.Reference = classReference
		}},
		{name: "removed R3 marker", change: func(invocation *HeldInvocation) {
			invocation.R3PerCall = nil
		}},
	} {
		held.loadResult = func(invocation HeldInvocation) HeldInvocation {
			scenario.change(&invocation)
			return invocation
		}
		changedStoredRequest := signedRequest(
			t, clock, agentKey, heldToken, http.MethodGet, heldChallenge.Header().Get("Location"), "",
		)
		changedStored := httptest.NewRecorder()
		server.Handler().ServeHTTP(changedStored, changedStoredRequest)
		held.loadResult = nil
		if changedStored.Code != http.StatusInternalServerError || applicationCalls.Load() != 2 {
			t.Fatalf(
				"%s = %d %s, application calls=%d",
				scenario.name, changedStored.Code, changedStored.Body.String(), applicationCalls.Load(),
			)
		}
	}
	held.loadResult = func(invocation HeldInvocation) HeldInvocation {
		invocation.R3PerCall.ExactProposal = []byte(`{"operation":{"name":"changed"}}`)
		return invocation
	}
	changedHeldProposalRequest := signedRequest(
		t, clock, agentKey, heldToken, http.MethodGet, heldChallenge.Header().Get("Location"), "",
	)
	changedHeldProposal := httptest.NewRecorder()
	server.Handler().ServeHTTP(changedHeldProposal, changedHeldProposalRequest)
	held.loadResult = nil
	if changedHeldProposal.Code != http.StatusInternalServerError || applicationCalls.Load() != 2 {
		t.Fatalf(
			"changed retained held proposal = %d %s, application calls=%d",
			changedHeldProposal.Code, changedHeldProposal.Body.String(), applicationCalls.Load(),
		)
	}
	poll := func() *httptest.ResponseRecorder {
		request := signedRequest(t, clock, agentKey, heldToken, http.MethodGet, heldChallenge.Header().Get("Location"), "")
		result := httptest.NewRecorder()
		server.Handler().ServeHTTP(result, request)
		return result
	}
	perCallConfig := config.R3.PerCall
	config.R3.PerCall = nil
	server, err = NewFederatedAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	now = time.Unix(heldClaims.ExpiresAt+1, 0)
	heldFirstRequest := signedRequest(t, clock, agentKey, heldToken, http.MethodGet, heldChallenge.Header().Get("Location"), "")
	heldFirstContext, cancelHeldTransport := context.WithCancel(heldFirstRequest.Context())
	heldFirstRequest = heldFirstRequest.WithContext(heldFirstContext)
	held.beforeClaim = cancelHeldTransport
	held.rejectCanceledClaim = true
	heldResult := httptest.NewRecorder()
	server.Handler().ServeHTTP(heldResult, heldFirstRequest)
	if heldResult.Code != http.StatusOK || heldResult.Body.String() != "{\"sequence\":3}\n" {
		t.Fatalf("held completion = %d %s", heldResult.Code, heldResult.Body.String())
	}
	heldReplay := poll()
	if heldReplay.Code != heldResult.Code || heldReplay.Body.String() != heldResult.Body.String() {
		t.Fatalf("held replay = %d %s", heldReplay.Code, heldReplay.Body.String())
	}
	if describeCalls.Load() != describesBeforeHeld+2 || applicationCalls.Load() != 3 {
		t.Fatalf("held describe/application calls = %d/%d", describeCalls.Load()-describesBeforeHeld, applicationCalls.Load())
	}
	if presentCalls.Load() != presentedBeforeHeld+2 {
		t.Fatalf("held present calls = %d, want one published and one duplicate challenge extraction", presentCalls.Load()-presentedBeforeHeld)
	}

	config.R3.PerCall = perCallConfig
	config.HeldInvocations = nil
	config.HoldAuthTokenRequest = nil
	expectedPrincipalScopes = []string{"records.write"}
	server, err = NewFederatedAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	prepareFailureRetry := func(authTokenID string) (r3.Reference, string) {
		t.Helper()
		challengeRequest := signedRequest(t, clock, agentKey, classAuthToken, http.MethodDelete, resourceIssuer+"/records/7", "")
		challengeResponse := httptest.NewRecorder()
		server.Handler().ServeHTTP(challengeResponse, challengeRequest)
		if challengeResponse.Code != http.StatusUnauthorized {
			t.Fatalf("failure-window challenge = %d %s", challengeResponse.Code, challengeResponse.Body.String())
		}
		requirement, err := aauth.ParseAuthTokenRequirement(challengeResponse.Header().Values("AAuth-Requirement"))
		if err != nil {
			t.Fatal(err)
		}
		_, reference, err := r3.VerifyResourceToken(context.Background(), requirement.ResourceToken, resolver, clock)
		if err != nil {
			t.Fatal(err)
		}
		proposalRecord, err := proposals.Load(context.Background(), reference.URI())
		if err != nil {
			t.Fatal(err)
		}
		compact, err := r3.MintPerCallAuthToken(registry, accessKey, aauth.AuthTokenClaims{
			Issuer: accessIssuer, DWK: aauth.AccessDiscoveryDocument,
			Audience: resourceIssuer, JTI: authTokenID,
			PersonServer: personIssuer, Subject: "person-1",
			Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
			IssuedAt:     now.Unix(), ExpiresAt: now.Add(30 * time.Minute).Unix(),
			Scope: "records.write", MissionS256: missionS256,
			Tenant: classResourceClaims.Tenant, Account: &account,
		}, reference, proposalRecord.ExactJSON)
		if err != nil {
			t.Fatal(err)
		}
		return reference, compact
	}
	callFailureRetry := func(compact string) *httptest.ResponseRecorder {
		request := signedRequest(t, clock, agentKey, compact, http.MethodDelete, resourceIssuer+"/records/7", "")
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		return response
	}

	definiteReference, definiteToken := prepareFailureRetry("definite-retain-auth-token")
	retries.retainErr = errors.New("definite retry retain failure")
	definiteFailure := callFailureRetry(definiteToken)
	retries.retainErr = nil
	if definiteFailure.Code != http.StatusInternalServerError || applicationCalls.Load() != 4 {
		t.Fatalf("definite retry retain failure = %d %s, application=%d", definiteFailure.Code, definiteFailure.Body.String(), applicationCalls.Load())
	}
	definiteReplay := callFailureRetry(definiteToken)
	if definiteReplay.Code != http.StatusInternalServerError || applicationCalls.Load() != 4 {
		t.Fatalf("definite retry recovery = %d %s, application=%d", definiteReplay.Code, definiteReplay.Body.String(), applicationCalls.Load())
	}
	if claims, retains := retries.observation(definiteReference); claims != 2 || retains != 0 {
		t.Fatalf("definite retry claims/retains = %d/%d", claims, retains)
	}

	uncertainReference, uncertainToken := prepareFailureRetry("uncertain-retain-auth-token")
	retries.retainAfterCommitErr = errors.New("retry retain result was lost")
	uncertainFailure := callFailureRetry(uncertainToken)
	retries.retainAfterCommitErr = nil
	if uncertainFailure.Code != http.StatusInternalServerError || applicationCalls.Load() != 5 {
		t.Fatalf("uncertain retry retain failure = %d %s, application=%d", uncertainFailure.Code, uncertainFailure.Body.String(), applicationCalls.Load())
	}
	uncertainReplay := callFailureRetry(uncertainToken)
	if uncertainReplay.Code != http.StatusOK || uncertainReplay.Body.String() != "{\"sequence\":5}\n" || applicationCalls.Load() != 5 {
		t.Fatalf("uncertain retry recovery = %d %s, application=%d", uncertainReplay.Code, uncertainReplay.Body.String(), applicationCalls.Load())
	}
	if claims, retains := retries.observation(uncertainReference); claims != 2 || retains != 1 {
		t.Fatalf("uncertain retry claims/retains = %d/%d", claims, retains)
	}
}

type r3ProposalTestStore struct {
	mu        sync.Mutex
	records   map[string]R3ProposalRecord
	commitErr error
}

func (store *r3ProposalTestStore) Commit(_ context.Context, record R3ProposalRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.commitErr != nil {
		return store.commitErr
	}
	if store.records == nil {
		store.records = make(map[string]R3ProposalRecord)
	}
	if _, ok := store.records[record.Reference.URI()]; ok {
		return ErrR3ProposalConflict
	}
	registry, err := resourceMCPRegistry()
	if err != nil {
		return err
	}
	if _, err := registry.ParseReferencedProposal(record.Reference, record.ExactJSON); err != nil {
		return err
	}
	record.ExactJSON = append([]byte(nil), record.ExactJSON...)
	store.records[record.Reference.URI()] = record
	return nil
}

func (store *r3ProposalTestStore) Load(_ context.Context, uri string) (R3ProposalRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[uri]
	if !ok {
		return R3ProposalRecord{}, ErrR3ProposalNotFound
	}
	record.ExactJSON = append([]byte(nil), record.ExactJSON...)
	return record, nil
}

func (store *r3ProposalTestStore) count() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.records)
}

type r3RetryTestStore struct {
	mu                   sync.Mutex
	records              map[string]*r3RetryTestEntry
	loadResult           func(R3RetryInvocation) R3RetryInvocation
	claimResult          *R3RetryClaim
	beforeClaim          func()
	rejectCanceledClaim  bool
	beforeRetain         func()
	rejectCanceledRetain bool
	retainErr            error
	retainAfterCommitErr error
	prepareErr           error
}

type r3RetryTestEntry struct {
	invocation R3RetryInvocation
	state      string
	token      R3RetryAuthToken
	fence      string
	response   HeldResponse
	claims     int
	retains    int
}

func (store *r3RetryTestStore) Prepare(_ context.Context, invocation R3RetryInvocation) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.prepareErr != nil {
		return store.prepareErr
	}
	if store.records == nil {
		store.records = make(map[string]*r3RetryTestEntry)
	}
	key := invocation.Reference.URI()
	if retained, ok := store.records[key]; ok {
		if !reflect.DeepEqual(retained.invocation, invocation) {
			return ErrR3RetryConflict
		}
		return nil
	}
	invocation.RequiredScopes = append([]string(nil), invocation.RequiredScopes...)
	invocation.ExactProposal = append([]byte(nil), invocation.ExactProposal...)
	store.records[key] = &r3RetryTestEntry{invocation: invocation, state: "pending"}
	return nil
}

func (store *r3RetryTestStore) Load(_ context.Context, reference r3.Reference) (R3RetryInvocation, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	entry, ok := store.records[reference.URI()]
	if !ok {
		return R3RetryInvocation{}, ErrR3RetryNotFound
	}
	invocation := entry.invocation
	invocation.RequiredScopes = append([]string(nil), invocation.RequiredScopes...)
	invocation.ExactProposal = append([]byte(nil), invocation.ExactProposal...)
	if store.loadResult != nil {
		invocation = store.loadResult(invocation)
	}
	return invocation, nil
}

func (store *r3RetryTestStore) Claim(ctx context.Context, reference r3.Reference, token R3RetryAuthToken) (R3RetryClaim, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.beforeClaim != nil {
		beforeClaim := store.beforeClaim
		store.beforeClaim = nil
		beforeClaim()
	}
	if store.rejectCanceledClaim && ctx.Err() != nil {
		return R3RetryClaim{}, ctx.Err()
	}
	entry, ok := store.records[reference.URI()]
	if !ok {
		return R3RetryClaim{}, ErrR3RetryNotFound
	}
	entry.claims++
	if store.claimResult != nil {
		return *store.claimResult, nil
	}
	switch entry.state {
	case "pending":
		if !token.PresentedAt.Before(entry.invocation.CompletionUntil) {
			return R3RetryClaim{}, ErrR3RetryExpired
		}
		entry.state = "executing"
		entry.token = token
		entry.fence = "fence-1"
		return NewHeldExecution(HeldExecution{InvocationID: reference.URI(), Fence: entry.fence}), nil
	case "executing":
		return R3RetryClaim{}, ErrR3RetryConflict
	case "completed":
		if entry.token.SHA256 != token.SHA256 {
			return R3RetryClaim{}, ErrR3RetryTokenMismatch
		}
		return NewHeldReplay(entry.response), nil
	case "unresolved":
		return R3RetryClaim{}, ErrR3RetryUnresolved
	default:
		return R3RetryClaim{}, ErrR3RetryConflict
	}
}

func (store *r3RetryTestStore) Retain(ctx context.Context, execution R3RetryExecution, response HeldResponse) (HeldResponse, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.beforeRetain != nil {
		beforeRetain := store.beforeRetain
		store.beforeRetain = nil
		beforeRetain()
	}
	if store.rejectCanceledRetain && ctx.Err() != nil {
		return HeldResponse{}, ctx.Err()
	}
	entry, ok := store.records[execution.InvocationID]
	if !ok || entry.state != "executing" || entry.fence != execution.Fence {
		return HeldResponse{}, ErrR3RetryCompletionStale
	}
	if store.retainErr != nil {
		entry.state = "unresolved"
		return HeldResponse{}, store.retainErr
	}
	entry.response = cloneHeldResponse(response)
	entry.state = "completed"
	entry.retains++
	if store.retainAfterCommitErr != nil {
		return HeldResponse{}, store.retainAfterCommitErr
	}
	return cloneHeldResponse(entry.response), nil
}

func (store *r3RetryTestStore) count() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.records)
}

func (store *r3RetryTestStore) observation(reference r3.Reference) (claims, retains int) {
	store.mu.Lock()
	defer store.mu.Unlock()
	entry := store.records[reference.URI()]
	if entry == nil {
		return 0, 0
	}
	return entry.claims, entry.retains
}

var _ R3ProposalStore = (*r3ProposalTestStore)(nil)
var _ R3RetryStore = (*r3RetryTestStore)(nil)
