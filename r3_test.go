package aauth

import (
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
		{"openapi gateway", R3VocabularyOpenAPIGateway, `{"service":"records","operationId":"readRecord"}`},
		{"grpc", R3VocabularyGRPC, `{"method":"records.RecordService/Read"}`},
		{"graphql", R3VocabularyGraphQL, `{"operation":"ReadRecord","type":"query"}`},
		{"asyncapi", R3VocabularyAsyncAPI, `{"operationId":"receiveRecord","action":"receive"}`},
		{"wsdl", R3VocabularyWSDL, `{"operation":"ReadRecord","service":"RecordService"}`},
		{"odata", R3VocabularyOData, `{"operation":"Records","methods":["GET"]}`},
	}
	for _, test := range tests {
		test := test
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

	invalid := []R3OperationSet{
		{Vocabulary: R3VocabularyMCP, Operations: []json.RawMessage{json.RawMessage(`{"operationId":"wrong"}`)}},
		{Vocabulary: R3VocabularyGRPC, Operations: []json.RawMessage{json.RawMessage(`{"method":"not-qualified"}`)}},
		{Vocabulary: R3VocabularyGraphQL, Operations: []json.RawMessage{json.RawMessage(`{"operation":"Read","type":"read"}`)}},
		{Vocabulary: R3VocabularyAsyncAPI, Operations: []json.RawMessage{json.RawMessage(`{"operationId":"event","action":"poll"}`)}},
		{Vocabulary: R3VocabularyOData, Operations: []json.RawMessage{json.RawMessage(`{"operation":"Records","methods":["get"]}`)}},
	}
	for index, set := range invalid {
		if err := set.Validate(); err == nil {
			t.Fatalf("invalid standard operation %d was accepted", index)
		}
	}
}

func TestR3OperationSetUsesSemanticSetEquality(t *testing.T) {
	t.Parallel()

	left := R3OperationSet{
		Vocabulary: R3VocabularyOpenAPIGateway,
		Operations: []json.RawMessage{
			json.RawMessage(`{"service":"records","operationId":"readRecord"}`),
			json.RawMessage(`{"service":"records","operationId":"writeRecord"}`),
		},
	}
	right := R3OperationSet{
		Vocabulary: R3VocabularyOpenAPIGateway,
		Operations: []json.RawMessage{
			json.RawMessage("{ \"operationId\": \"writeRecord\", \"service\": \"records\" }"),
			json.RawMessage(`{"operationId":"readRecord","service":"records"}`),
		},
	}
	if !left.Equal(right) {
		t.Fatalf("semantically equal operation sets differ:\nleft: %#v\nright: %#v", left, right)
	}
	if !left.ContainsSet(R3OperationSet{
		Vocabulary: R3VocabularyOpenAPIGateway,
		Operations: []json.RawMessage{json.RawMessage(`{"operationId":"readRecord","service":"records"}`)},
	}) {
		t.Fatal("operation set does not contain its semantic subset")
	}
}

func TestR3DocumentHashRetainsExactWireIdentity(t *testing.T) {
	t.Parallel()

	compact := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}]}`)
	spaced := []byte(`{"vocabulary": "urn:aauth:vocabulary:mcp", "operations": [{"tool":"read"}]}`)
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

	_, err = ParseR3Document([]byte(
		`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}],"display":{}}`,
	))
	if err == nil || !strings.Contains(err.Error(), "display.summary") {
		t.Fatalf("missing display summary error = %v", err)
	}
}

func TestR3TokenClaimsRequireCompleteConsistentClaims(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC)
	key := internalTestSigningKey(t, "access-key")
	agentKey := internalTestSigningKey(t, "agent-key")
	operations := &R3OperationSet{
		Vocabulary: R3VocabularyMCP,
		Operations: []json.RawMessage{json.RawMessage(`{"tool":"read"}`)},
	}
	document := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}]}`)
	valid := AuthTokenClaims{
		Issuer:        "https://as.example",
		DWK:           AccessDiscoveryDocument,
		Audience:      "https://resource.example",
		JTI:           "auth-token",
		Agent:         "aauth:planner@ap.example",
		Confirmation:  Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(time.Hour).Unix(),
		Subject:       "pairwise-user",
		Scope:         "records.read",
		R3URI:         "https://resource.example/r3/" + R3S256(document),
		R3S256:        R3S256(document),
		R3Granted:     operations,
		R3Conditional: nil,
	}
	if _, err := MintAuthToken(key, valid); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*AuthTokenClaims)
	}{
		{"missing hash", func(claims *AuthTokenClaims) { claims.R3S256 = "" }},
		{"missing grant", func(claims *AuthTokenClaims) { claims.R3Granted = nil }},
		{"grant without reference", func(claims *AuthTokenClaims) {
			claims.R3URI = ""
			claims.R3S256 = ""
		}},
		{"overlapping conditional grant", func(claims *AuthTokenClaims) {
			conditional := operations.Clone()
			claims.R3Conditional = &conditional
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			claims := valid
			granted := operations.Clone()
			claims.R3Granted = &granted
			test.mutate(&claims)
			if _, err := MintAuthToken(key, claims); err == nil {
				t.Fatal("invalid R3 claims were minted")
			}
		})
	}
}
