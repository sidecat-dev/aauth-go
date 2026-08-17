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

func TestR3ProposalBindsInlineAndDigestParameters(t *testing.T) {
	t.Parallel()

	operation := R3OperationSet{
		Vocabulary: R3VocabularyMCP,
		Operations: []json.RawMessage{json.RawMessage(`{"tool":"send_message"}`)},
	}
	proposal := R3Proposal{
		Parameters: map[string]R3CallParameter{
			"recipient": {Value: json.RawMessage(`"person@example.com"`)},
			"body": {
				Digest:         true,
				PresentedValue: []byte("hello from the exact request body"),
				Excerpt:        "hello from...",
				MediaType:      "text/plain",
			},
		},
		Display: &R3Display{
			Summary: "Send one message",
			Detail:  "## Recipient\nperson@example.com",
		},
	}
	exactBytes, err := BuildR3Proposal(operation, proposal)
	if err != nil {
		t.Fatal(err)
	}
	document, err := ParseR3Document(exactBytes)
	if err != nil {
		t.Fatal(err)
	}
	if document.Parameters == nil || document.Display == nil ||
		document.Display.Detail != proposal.Display.Detail {
		t.Fatalf("parsed proposal = %#v", document)
	}
	if strings.Contains(string(exactBytes), "hello from the exact request body") {
		t.Fatalf("digested body leaked into proposal: %s", exactBytes)
	}
	if err := document.MatchR3Call(operation, proposal.Parameters); err != nil {
		t.Fatalf("matching call parameters were refused: %v", err)
	}

	changedBody := cloneR3CallParameters(proposal.Parameters)
	changedBody["body"] = R3CallParameter{
		Digest:         true,
		PresentedValue: []byte("hello from a changed request body"),
		Excerpt:        proposal.Parameters["body"].Excerpt,
		MediaType:      "text/plain",
	}
	if err := document.MatchR3Call(operation, changedBody); err == nil ||
		!strings.Contains(err.Error(), "body") {
		t.Fatalf("changed digest bytes error = %v", err)
	}

	changedRecipient := cloneR3CallParameters(proposal.Parameters)
	changedRecipient["recipient"] = R3CallParameter{Value: json.RawMessage(`"other@example.com"`)}
	if err := document.MatchR3Call(operation, changedRecipient); err == nil ||
		!strings.Contains(err.Error(), "recipient") {
		t.Fatalf("changed inline parameter error = %v", err)
	}

	missingParameter := cloneR3CallParameters(proposal.Parameters)
	delete(missingParameter, "recipient")
	if err := document.MatchR3Call(operation, missingParameter); err == nil {
		t.Fatal("call with a missing parameter was accepted")
	}

	extraParameter := cloneR3CallParameters(proposal.Parameters)
	extraParameter["priority"] = R3CallParameter{Value: json.RawMessage(`"urgent"`)}
	if err := document.MatchR3Call(operation, extraParameter); err == nil {
		t.Fatal("call with an extra parameter was accepted")
	}

	changedMediaType := cloneR3CallParameters(proposal.Parameters)
	body := changedMediaType["body"]
	body.MediaType = "application/octet-stream"
	changedMediaType["body"] = body
	if err := document.MatchR3Call(operation, changedMediaType); err == nil {
		t.Fatal("digest parameter with changed media type was accepted")
	}

	changedOperation := R3OperationSet{
		Vocabulary: R3VocabularyMCP,
		Operations: []json.RawMessage{json.RawMessage(`{"tool":"delete_message"}`)},
	}
	if err := document.MatchR3Call(changedOperation, proposal.Parameters); err == nil {
		t.Fatal("call with a changed operation was accepted")
	}
}

func TestR3ProposalRejectsMalformedParameterDocuments(t *testing.T) {
	t.Parallel()

	for name, exactBytes := range map[string][]byte{
		"zero operations": []byte(
			`{"vocabulary":"urn:aauth:vocabulary:mcp",` +
				`"operations":[],"parameters":{"recipient":"person@example.com"}}`,
		),
		"null parameters": []byte(
			`{"vocabulary":"urn:aauth:vocabulary:mcp",` +
				`"operations":[{"tool":"send_message"}],"parameters":null}`,
		),
		"invalid digest": []byte(
			`{"vocabulary":"urn:aauth:vocabulary:mcp",` +
				`"operations":[{"tool":"send_message"}],` +
				`"parameters":{"body":{"s256":"not-a-digest"}}}`,
		),
		"empty digest": []byte(
			`{"vocabulary":"urn:aauth:vocabulary:mcp",` +
				`"operations":[{"tool":"send_message"}],` +
				`"parameters":{"body":{"s256":""}}}`,
		),
		"array parameters": []byte(
			`{"vocabulary":"urn:aauth:vocabulary:mcp",` +
				`"operations":[{"tool":"send_message"}],"parameters":[]}`,
		),
		"unknown digest member": []byte(
			`{"vocabulary":"urn:aauth:vocabulary:mcp",` +
				`"operations":[{"tool":"send_message"}],` +
				`"parameters":{"body":{"s256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","value":"secret"}}}`,
		),
		"multiple operations": []byte(
			`{"vocabulary":"urn:aauth:vocabulary:mcp",` +
				`"operations":[{"tool":"send_message"},{"tool":"delete_message"}],` +
				`"parameters":{"recipient":"person@example.com"}}`,
		),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseR3Document(exactBytes); err == nil {
				t.Fatalf("malformed proposal was accepted: %s", exactBytes)
			}
		})
	}
	operation := R3OperationSet{
		Vocabulary: R3VocabularyMCP,
		Operations: []json.RawMessage{json.RawMessage(`{"tool":"send_message"}`)},
	}
	if _, err := BuildR3Proposal(operation, R3Proposal{}); err == nil {
		t.Fatal("proposal without parameters was built")
	}
}

func TestR3DocumentRejectsDuplicateNamesAtEveryDepth(t *testing.T) {
	t.Parallel()

	for name, exactBytes := range map[string][]byte{
		"top-level vocabulary": []byte(
			`{"vocabulary":"urn:aauth:vocabulary:mcp",` +
				`"vocabulary":"urn:aauth:vocabulary:mcp",` +
				`"operations":[{"tool":"read"}]}`,
		),
		"top-level operations": []byte(
			`{"vocabulary":"urn:aauth:vocabulary:mcp",` +
				`"operations":[{"tool":"read"}],` +
				`"operations":[{"tool":"read"}]}`,
		),
		"nested display": []byte(
			`{"vocabulary":"urn:aauth:vocabulary:mcp",` +
				`"operations":[{"tool":"read"}],` +
				`"display":{"summary":"Read","summary":"Read"}}`,
		),
		"case-variant vocabulary alias": []byte(
			`{"vocabulary":"urn:aauth:vocabulary:mcp",` +
				`"Vocabulary":"urn:aauth:vocabulary:mcp",` +
				`"operations":[{"tool":"read"}]}`,
		),
		"case-variant nested display alias": []byte(
			`{"vocabulary":"urn:aauth:vocabulary:mcp",` +
				`"operations":[{"tool":"read"}],` +
				`"display":{"summary":"Read","SUMMARY":"Read"}}`,
		),
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

func TestVerifyAuthTokenRejectsDuplicateR3Claims(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 2, 18, 0, 0, 0, time.UTC)
	accessKey := internalTestSigningKey(t, "access-key")
	agentKey := internalTestSigningKey(t, "agent-key")
	document := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}]}`)
	digest := R3S256(document)
	granted := &R3OperationSet{
		Vocabulary: R3VocabularyMCP,
		Operations: []json.RawMessage{json.RawMessage(`{"tool":"read"}`)},
	}
	claims, err := json.Marshal(AuthTokenClaims{
		Issuer:       "https://as.example",
		DWK:          AccessDiscoveryDocument,
		Audience:     "https://resource.example",
		JTI:          "auth-token",
		Agent:        "aauth:planner@ap.example",
		Confirmation: Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(time.Hour).Unix(),
		Subject:      "pairwise-user",
		Scope:        "records.read",
		R3URI:        "https://resource.example/r3/" + digest,
		R3S256:       digest,
		R3Granted:    granted,
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, claimName := range map[string]string{
		"exact duplicate":    "r3_s256",
		"case-variant alias": "R3_S256",
	} {
		t.Run(name, func(t *testing.T) {
			ambiguousClaims := append(
				[]byte(`{"`+claimName+`":"`+digest+`",`),
				claims[1:]...,
			)
			compact := signRawTestToken(t, accessKey, AuthTokenType, ambiguousClaims)
			_, err := VerifyAuthToken(
				context.Background(),
				compact,
				StaticKeyResolver{
					"https://as.example": {"access-key": accessKey.PublicJWK()},
				},
				ClockFunc(func() time.Time { return now }),
			)
			if err == nil || (!strings.Contains(err.Error(), "duplicate object name") &&
				!strings.Contains(err.Error(), "case-ambiguous object names")) {
				t.Fatalf("ambiguous R3 claim error = %v", err)
			}
		})
	}
}

func signRawTestToken(
	t *testing.T,
	key SigningKey,
	tokenType string,
	claims []byte,
) string {
	t.Helper()
	header, err := json.Marshal(TokenHeader{
		Algorithm: "Ed25519",
		Type:      tokenType,
		KeyID:     key.ID(),
	})
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
