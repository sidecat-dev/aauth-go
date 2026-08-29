package aauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestR3StandardVocabularyOperationShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		vocabulary string
		operation  string
	}{
		{"mcp", r3.VocabularyMCP, `{"tool":"read_record"}`},
		{"openapi", r3.VocabularyOpenAPI, `{"operationId":"readRecord"}`},
		{"grpc", r3.VocabularyGRPC, `{"method":"records.RecordService/Read"}`},
		{"graphql", r3.VocabularyGraphQL, `{"operation":"ReadRecord","type":"query"}`},
		{"asyncapi", r3.VocabularyAsyncAPI, `{"operationId":"receiveRecord","action":"receive"}`},
		{"wsdl", r3.VocabularyWSDL, `{"operation":"ReadRecord","service":"RecordService"}`},
		{"odata", r3.VocabularyOData, `{"operation":"Records","methods":["GET"]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			set := r3.OperationSet{
				Vocabulary: test.vocabulary,
				Operations: []json.RawMessage{json.RawMessage(test.operation)},
			}
			if err := set.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}

	for index, set := range []r3.OperationSet{
		{Vocabulary: "urn:aauth:vocabulary:openapi-gateway", Operations: []json.RawMessage{json.RawMessage(`{"service":"records","operationId":"read"}`)}},
		{Vocabulary: r3.VocabularyMCP, Operations: []json.RawMessage{json.RawMessage(`{"operationId":"wrong"}`)}},
		{Vocabulary: r3.VocabularyGRPC, Operations: []json.RawMessage{json.RawMessage(`{"method":"not-qualified"}`)}},
		{Vocabulary: r3.VocabularyGraphQL, Operations: []json.RawMessage{json.RawMessage(`{"operation":"Read","type":"read"}`)}},
		{Vocabulary: r3.VocabularyAsyncAPI, Operations: []json.RawMessage{json.RawMessage(`{"operationId":"event","action":"poll"}`)}},
		{Vocabulary: r3.VocabularyOData, Operations: []json.RawMessage{json.RawMessage(`{"operation":"Records","methods":["get"]}`)}},
	} {
		if err := set.Validate(); err == nil {
			t.Fatalf("invalid standard operation %d was accepted", index)
		}
	}
}

func TestR3OperationSetUsesSemanticSetEquality(t *testing.T) {
	t.Parallel()

	left := r3.OperationSet{
		Vocabulary: r3.VocabularyOpenAPI,
		Operations: []json.RawMessage{
			json.RawMessage(`{"operationId":"readRecord"}`),
			json.RawMessage(`{"operationId":"writeRecord"}`),
		},
	}
	right := r3.OperationSet{
		Vocabulary: r3.VocabularyOpenAPI,
		Operations: []json.RawMessage{
			json.RawMessage(`{ "operationId": "writeRecord" }`),
			json.RawMessage(`{"operationId":"readRecord"}`),
		},
	}
	if !left.Equal(right) {
		t.Fatalf("semantically equal operation sets differ:\nleft: %#v\nright: %#v", left, right)
	}
	if !left.ContainsSet(r3.OperationSet{
		Vocabulary: r3.VocabularyOpenAPI,
		Operations: []json.RawMessage{json.RawMessage(`{"operationId":"readRecord"}`)},
	}) {
		t.Fatal("operation set does not contain its semantic subset")
	}
}

func TestR3DocumentRetainsExactIdentityAndCurrentNeutralShape(t *testing.T) {
	t.Parallel()

	compact := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"send_email"}],"account":"work-account","parameters":{"to":"person@example.com","body":{"s256":"abc","media_type":"text/plain"}},"display":{"summary":"Send email","detail":"## To\nperson@example.com"}}`)
	spaced := []byte(`{ "vocabulary": "urn:aauth:vocabulary:mcp", "operations": [{"tool":"send_email"}], "account": "work-account", "parameters": {"to":"person@example.com","body":{"s256":"abc","media_type":"text/plain"}}, "display": {"summary":"Send email","detail":"## To\nperson@example.com"} }`)
	compactDocument, err := r3.ParseDocument(compact)
	if err != nil {
		t.Fatal(err)
	}
	spacedDocument, err := r3.ParseDocument(spaced)
	if err != nil {
		t.Fatal(err)
	}
	if !compactDocument.OperationSet().Equal(spacedDocument.OperationSet()) {
		t.Fatal("equivalent R3 documents produced different operation sets")
	}
	if r3.S256(compact) == r3.S256(spaced) {
		t.Fatal("different exact R3 bytes produced the same test digest")
	}
	if len(r3.S256(compact)) != 43 {
		t.Fatalf("R3 SHA-256 base64url length = %d, want 43", len(r3.S256(compact)))
	}
	encoded, err := json.Marshal(compactDocument)
	if err != nil {
		t.Fatal(err)
	}
	for _, member := range []string{`"account":"work-account"`, `"parameters":`, `"detail":"## To\nperson@example.com"`} {
		if !strings.Contains(string(encoded), member) {
			t.Fatalf("parsed current R3 document does not retain %s: %s", member, encoded)
		}
	}
}

func TestParseR3DocumentRejectsRemovedAndMalformedMembers(t *testing.T) {
	t.Parallel()

	for name, exactBytes := range map[string][]byte{
		"removed version":  []byte(`{"version":"1","vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}]}`),
		"unknown member":   []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}],"grant":true}`),
		"null parameters":  []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}],"parameters":null}`),
		"array parameters": []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}],"parameters":[]}`),
		"empty display":    []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}],"display":{}}`),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := r3.ParseDocument(exactBytes); err == nil {
				t.Fatalf("invalid R3 document was accepted: %s", exactBytes)
			}
		})
	}
}

func TestR3DocumentRejectsDuplicateNamesAtEveryDepth(t *testing.T) {
	t.Parallel()

	for name, exactBytes := range map[string][]byte{
		"top-level vocabulary":    []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}]}`),
		"nested parameters":       []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}],"parameters":{"key":1,"key":2}}`),
		"case-variant vocabulary": []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","Vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}]}`),
		"case-variant display":    []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}],"display":{"summary":"Read","SUMMARY":"Read"}}`),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := r3.ParseDocument(exactBytes); err == nil ||
				(!strings.Contains(err.Error(), "duplicate object name") &&
					!strings.Contains(err.Error(), "case-ambiguous object names")) {
				t.Fatalf("duplicate-name error = %v", err)
			}
		})
	}
}

func TestVerifyTokensRejectRawUnsupportedExtensionMembersBeforeClaimsDecode(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 28, 22, 0, 0, 0, time.UTC)
	issuerKey := internalTestSigningKey(t, "issuer-key")
	agentKey := internalTestSigningKey(t, "agent-key")
	resourceBase, err := json.Marshal(ResourceTokenClaims{
		Issuer:       "https://resource.example",
		DWK:          ResourceDiscoveryDocument,
		Audience:     "https://ps.example",
		JTI:          "resource-token",
		AgentJKT:     "agent-thumbprint",
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(time.Minute).Unix(),
		Scope:        "records.read",
		PersonServer: "https://ps.example",
		Subject:      "pairwise-user",
		PresentedJTI: "person-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	authBase, err := json.Marshal(AuthTokenClaims{
		Issuer:       "https://as.example",
		DWK:          AccessDiscoveryDocument,
		Audience:     "https://resource.example",
		JTI:          "auth-token",
		Confirmation: Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(time.Hour).Unix(),
		Subject:      "pairwise-user",
		Scope:        "records.read",
		PersonServer: "https://ps.example",
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name      string
		tokenType string
		base      []byte
		member    string
		value     string
		verify    func(string) error
	}{
		{"resource r3_uri", ResourceTokenType, resourceBase, "r3_uri", `"https://resource.example/r3/document"`, func(compact string) error {
			_, err := VerifyResourceToken(context.Background(), compact, signaturekey.StaticKeyResolver{"https://resource.example": {issuerKey.ID(): issuerKey.PublicJWK()}}, ClockFunc(func() time.Time { return now }))
			return err
		}},
		{"resource r3_s256", ResourceTokenType, resourceBase, "r3_s256", `"digest"`, func(compact string) error {
			_, err := VerifyResourceToken(context.Background(), compact, signaturekey.StaticKeyResolver{"https://resource.example": {issuerKey.ID(): issuerKey.PublicJWK()}}, ClockFunc(func() time.Time { return now }))
			return err
		}},
		{"resource budget", ResourceTokenType, resourceBase, "budget", `{"amount":100,"unit":"USD","decimals":2}`, func(compact string) error {
			_, err := VerifyResourceToken(context.Background(), compact, signaturekey.StaticKeyResolver{"https://resource.example": {issuerKey.ID(): issuerKey.PublicJWK()}}, ClockFunc(func() time.Time { return now }))
			return err
		}},
		{"resource budget_consumed", ResourceTokenType, resourceBase, "budget_consumed", `[{"jti":"auth-1","consumed":10}]`, func(compact string) error {
			_, err := VerifyResourceToken(context.Background(), compact, signaturekey.StaticKeyResolver{"https://resource.example": {issuerKey.ID(): issuerKey.PublicJWK()}}, ClockFunc(func() time.Time { return now }))
			return err
		}},
		{"auth r3_uri", AuthTokenType, authBase, "r3_uri", `"https://resource.example/r3/document"`, func(compact string) error {
			_, err := VerifyAuthToken(context.Background(), compact, signaturekey.StaticKeyResolver{"https://as.example": {issuerKey.ID(): issuerKey.PublicJWK()}}, ClockFunc(func() time.Time { return now }))
			return err
		}},
		{"auth r3_s256", AuthTokenType, authBase, "r3_s256", `"digest"`, func(compact string) error {
			_, err := VerifyAuthToken(context.Background(), compact, signaturekey.StaticKeyResolver{"https://as.example": {issuerKey.ID(): issuerKey.PublicJWK()}}, ClockFunc(func() time.Time { return now }))
			return err
		}},
		{"auth r3_granted", AuthTokenType, authBase, "r3_granted", `{}`, func(compact string) error {
			_, err := VerifyAuthToken(context.Background(), compact, signaturekey.StaticKeyResolver{"https://as.example": {issuerKey.ID(): issuerKey.PublicJWK()}}, ClockFunc(func() time.Time { return now }))
			return err
		}},
		{"auth r3_per_call", AuthTokenType, authBase, "r3_per_call", `{}`, func(compact string) error {
			_, err := VerifyAuthToken(context.Background(), compact, signaturekey.StaticKeyResolver{"https://as.example": {issuerKey.ID(): issuerKey.PublicJWK()}}, ClockFunc(func() time.Time { return now }))
			return err
		}},
		{"auth r3_conditional", AuthTokenType, authBase, "r3_conditional", `{}`, func(compact string) error {
			_, err := VerifyAuthToken(context.Background(), compact, signaturekey.StaticKeyResolver{"https://as.example": {issuerKey.ID(): issuerKey.PublicJWK()}}, ClockFunc(func() time.Time { return now }))
			return err
		}},
		{"auth budget", AuthTokenType, authBase, "budget", `{"amount":100,"unit":"USD","decimals":2}`, func(compact string) error {
			_, err := VerifyAuthToken(context.Background(), compact, signaturekey.StaticKeyResolver{"https://as.example": {issuerKey.ID(): issuerKey.PublicJWK()}}, ClockFunc(func() time.Time { return now }))
			return err
		}},
		{"auth budget_consumed", AuthTokenType, authBase, "budget_consumed", `[{"jti":"auth-1","consumed":10}]`, func(compact string) error {
			_, err := VerifyAuthToken(context.Background(), compact, signaturekey.StaticKeyResolver{"https://as.example": {issuerKey.ID(): issuerKey.PublicJWK()}}, ClockFunc(func() time.Time { return now }))
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			payload := append(append([]byte(nil), test.base[:len(test.base)-1]...), []byte(`,"`+test.member+`":`+test.value+`,"account":[]}`)...)
			compact := signRawTestToken(t, issuerKey, test.tokenType, payload)
			err := test.verify(compact)
			if err == nil || !strings.Contains(err.Error(), "unsupported") || !strings.Contains(err.Error(), test.member) {
				t.Fatalf("unsupported %s error = %v", test.member, err)
			}
		})
	}
}

func signRawTestToken(t *testing.T, key jose.SigningKey, tokenType string, claims []byte) string {
	t.Helper()
	header, err := json.Marshal(jose.Header{Algorithm: jose.Ed25519Algorithm, Type: tokenType, KeyID: key.ID()})
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	signature, err := signTestMessage(key, []byte(signingInput))
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}
