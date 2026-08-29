package aauth

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestR3StandardVocabularyOperationShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		vocabulary string
		operation  string
	}{
		{"mcp", R3VocabularyMCP, `{"tool":"read_record"}`},
		{"openapi", R3VocabularyOpenAPI, `{"operationId":"readRecord"}`},
		{"grpc", R3VocabularyGRPC, `{"method":"records.RecordService/Read"}`},
		{"graphql", R3VocabularyGraphQL, `{"operation":"ReadRecord","type":"query"}`},
		{"asyncapi", R3VocabularyAsyncAPI, `{"operationId":"receiveRecord","action":"receive"}`},
		{"wsdl", R3VocabularyWSDL, `{"operation":"ReadRecord","service":"RecordService"}`},
		{"odata", R3VocabularyOData, `{"operation":"Records","methods":["GET"]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			set := R3OperationSet{
				Vocabulary: test.vocabulary,
				Operations: []json.RawMessage{json.RawMessage(test.operation)},
			}
			if err := set.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}

	for index, set := range []R3OperationSet{
		{Vocabulary: "urn:aauth:vocabulary:openapi-gateway", Operations: []json.RawMessage{json.RawMessage(`{"service":"records","operationId":"read"}`)}},
		{Vocabulary: R3VocabularyMCP, Operations: []json.RawMessage{json.RawMessage(`{"operationId":"wrong"}`)}},
		{Vocabulary: R3VocabularyGRPC, Operations: []json.RawMessage{json.RawMessage(`{"method":"not-qualified"}`)}},
		{Vocabulary: R3VocabularyGraphQL, Operations: []json.RawMessage{json.RawMessage(`{"operation":"Read","type":"read"}`)}},
		{Vocabulary: R3VocabularyAsyncAPI, Operations: []json.RawMessage{json.RawMessage(`{"operationId":"event","action":"poll"}`)}},
		{Vocabulary: R3VocabularyOData, Operations: []json.RawMessage{json.RawMessage(`{"operation":"Records","methods":["get"]}`)}},
	} {
		if err := set.Validate(); err == nil {
			t.Fatalf("invalid standard operation %d was accepted", index)
		}
	}
}

func TestR3OperationSetUsesSemanticSetEquality(t *testing.T) {
	t.Parallel()

	left := R3OperationSet{
		Vocabulary: R3VocabularyOpenAPI,
		Operations: []json.RawMessage{
			json.RawMessage(`{"operationId":"readRecord"}`),
			json.RawMessage(`{"operationId":"writeRecord"}`),
		},
	}
	right := R3OperationSet{
		Vocabulary: R3VocabularyOpenAPI,
		Operations: []json.RawMessage{
			json.RawMessage(`{ "operationId": "writeRecord" }`),
			json.RawMessage(`{"operationId":"readRecord"}`),
		},
	}
	if !left.Equal(right) {
		t.Fatalf("semantically equal operation sets differ:\nleft: %#v\nright: %#v", left, right)
	}
	if !left.ContainsSet(R3OperationSet{
		Vocabulary: R3VocabularyOpenAPI,
		Operations: []json.RawMessage{json.RawMessage(`{"operationId":"readRecord"}`)},
	}) {
		t.Fatal("operation set does not contain its semantic subset")
	}
}

func TestR3DocumentRetainsExactIdentityAndCurrentNeutralShape(t *testing.T) {
	t.Parallel()

	compact := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"send_email"}],"account":"work-account","parameters":{"to":"person@example.com","body":{"s256":"abc","media_type":"text/plain"}},"display":{"summary":"Send email","detail":"## To\nperson@example.com"}}`)
	spaced := []byte(`{ "vocabulary": "urn:aauth:vocabulary:mcp", "operations": [{"tool":"send_email"}], "account": "work-account", "parameters": {"to":"person@example.com","body":{"s256":"abc","media_type":"text/plain"}}, "display": {"summary":"Send email","detail":"## To\nperson@example.com"} }`)
	compactDocument, err := ParseR3Document(compact)
	if err != nil {
		t.Fatal(err)
	}
	spacedDocument, err := ParseR3Document(spaced)
	if err != nil {
		t.Fatal(err)
	}
	if !compactDocument.OperationSet().Equal(spacedDocument.OperationSet()) {
		t.Fatal("equivalent R3 documents produced different operation sets")
	}
	if R3S256(compact) == R3S256(spaced) {
		t.Fatal("different exact R3 bytes produced the same test digest")
	}
	if len(R3S256(compact)) != 43 {
		t.Fatalf("R3 SHA-256 base64url length = %d, want 43", len(R3S256(compact)))
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
			if _, err := ParseR3Document(exactBytes); err == nil {
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
			if _, err := ParseR3Document(exactBytes); err == nil ||
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
			_, err := VerifyResourceToken(context.Background(), compact, StaticKeyResolver{"https://resource.example": {issuerKey.ID(): issuerKey.PublicJWK()}}, ClockFunc(func() time.Time { return now }))
			return err
		}},
		{"resource r3_s256", ResourceTokenType, resourceBase, "r3_s256", `"digest"`, func(compact string) error {
			_, err := VerifyResourceToken(context.Background(), compact, StaticKeyResolver{"https://resource.example": {issuerKey.ID(): issuerKey.PublicJWK()}}, ClockFunc(func() time.Time { return now }))
			return err
		}},
		{"resource budget", ResourceTokenType, resourceBase, "budget", `{"amount":100,"unit":"USD","decimals":2}`, func(compact string) error {
			_, err := VerifyResourceToken(context.Background(), compact, StaticKeyResolver{"https://resource.example": {issuerKey.ID(): issuerKey.PublicJWK()}}, ClockFunc(func() time.Time { return now }))
			return err
		}},
		{"resource budget_consumed", ResourceTokenType, resourceBase, "budget_consumed", `[{"jti":"auth-1","consumed":10}]`, func(compact string) error {
			_, err := VerifyResourceToken(context.Background(), compact, StaticKeyResolver{"https://resource.example": {issuerKey.ID(): issuerKey.PublicJWK()}}, ClockFunc(func() time.Time { return now }))
			return err
		}},
		{"auth r3_uri", AuthTokenType, authBase, "r3_uri", `"https://resource.example/r3/document"`, func(compact string) error {
			_, err := VerifyAuthToken(context.Background(), compact, StaticKeyResolver{"https://as.example": {issuerKey.ID(): issuerKey.PublicJWK()}}, ClockFunc(func() time.Time { return now }))
			return err
		}},
		{"auth r3_s256", AuthTokenType, authBase, "r3_s256", `"digest"`, func(compact string) error {
			_, err := VerifyAuthToken(context.Background(), compact, StaticKeyResolver{"https://as.example": {issuerKey.ID(): issuerKey.PublicJWK()}}, ClockFunc(func() time.Time { return now }))
			return err
		}},
		{"auth r3_granted", AuthTokenType, authBase, "r3_granted", `{}`, func(compact string) error {
			_, err := VerifyAuthToken(context.Background(), compact, StaticKeyResolver{"https://as.example": {issuerKey.ID(): issuerKey.PublicJWK()}}, ClockFunc(func() time.Time { return now }))
			return err
		}},
		{"auth r3_per_call", AuthTokenType, authBase, "r3_per_call", `{}`, func(compact string) error {
			_, err := VerifyAuthToken(context.Background(), compact, StaticKeyResolver{"https://as.example": {issuerKey.ID(): issuerKey.PublicJWK()}}, ClockFunc(func() time.Time { return now }))
			return err
		}},
		{"auth r3_conditional", AuthTokenType, authBase, "r3_conditional", `{}`, func(compact string) error {
			_, err := VerifyAuthToken(context.Background(), compact, StaticKeyResolver{"https://as.example": {issuerKey.ID(): issuerKey.PublicJWK()}}, ClockFunc(func() time.Time { return now }))
			return err
		}},
		{"auth budget", AuthTokenType, authBase, "budget", `{"amount":100,"unit":"USD","decimals":2}`, func(compact string) error {
			_, err := VerifyAuthToken(context.Background(), compact, StaticKeyResolver{"https://as.example": {issuerKey.ID(): issuerKey.PublicJWK()}}, ClockFunc(func() time.Time { return now }))
			return err
		}},
		{"auth budget_consumed", AuthTokenType, authBase, "budget_consumed", `[{"jti":"auth-1","consumed":10}]`, func(compact string) error {
			_, err := VerifyAuthToken(context.Background(), compact, StaticKeyResolver{"https://as.example": {issuerKey.ID(): issuerKey.PublicJWK()}}, ClockFunc(func() time.Time { return now }))
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

func signRawTestToken(t *testing.T, key SigningKey, tokenType string, claims []byte) string {
	t.Helper()
	header, err := json.Marshal(TokenHeader{Algorithm: Ed25519Algorithm, Type: tokenType, KeyID: key.ID()})
	if err != nil {
		t.Fatal(err)
	}
	signingInput := rawURL.EncodeToString(header) + "." + rawURL.EncodeToString(claims)
	signature, err := key.sign([]byte(signingInput))
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + rawURL.EncodeToString(signature)
}
