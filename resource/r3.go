package resource

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	aauth "aauth-go"
	"aauth-go/r3"
	"aauth-go/signaturekey"
)

// MCPR3Config enables the direct-grant MCP profile on a federated Resource.
// Core-only authorization remains available when r3_operations is absent.
type MCPR3Config struct {
	// DiscoveryEndpoint is the Resource's one advertised MCP server URL.
	DiscoveryEndpoint string
	// KnownTools is an authoritative snapshot of that MCP server's tool names.
	KnownTools []string
	// Documents retains exact bytes and their PS/AS fetch entitlement.
	Documents R3DocumentStore
	// DisplayForOperations optionally supplies the human-readable consequences
	// that the Person Server presents during consent.
	DisplayForOperations func(context.Context, r3.MCPOperationSet, *string) (*r3.Display, error)
	// OperationForRequest maps a protected request to an MCP tool. A false ok
	// identifies a Core-only route. The supplied request is an independent
	// policy view whose body may be read without consuming the application body.
	OperationForRequest func(*http.Request) (tool string, ok bool, err error)
}

type mcpR3ProtectedAuthorization struct {
	reference r3.Reference
	granted   r3.GrantedOperations
}

func (server *Server) issueMCPR3ResourceToken(
	ctx context.Context,
	claims aauth.ResourceTokenClaims,
	operations r3.MCPOperationSet,
) (string, error) {
	var display *r3.Display
	var err error
	if server.mcpR3.displayForOperations != nil {
		display, err = server.mcpR3.displayForOperations(
			ctx, operations, cloneAuthorizationAccount(claims.Account),
		)
		if err != nil {
			return "", fmt.Errorf("aauth: describe MCP R3 operations: %w", err)
		}
	}
	document, err := r3.NewDocument(operations, r3.DocumentOptions{
		Account: cloneAuthorizationAccount(claims.Account), Display: display,
	})
	if err != nil {
		return "", err
	}
	exactJSON, err := json.Marshal(document)
	if err != nil {
		return "", fmt.Errorf("aauth: serialize MCP R3 document: %w", err)
	}
	documentURI := mcpR3DocumentURI(server.issuer, exactJSON, claims.PersonServer, claims.Audience)
	compact, reference, err := r3.MintMCPResourceToken(server.signingKey, claims, documentURI, exactJSON)
	if err != nil {
		return "", err
	}
	record := R3DocumentRecord{
		Reference: reference, ExactJSON: append([]byte(nil), exactJSON...),
		PersonServer: claims.PersonServer, AccessServer: claims.Audience,
	}
	if err := server.mcpR3.documents.Commit(ctx, record); err != nil {
		return "", fmt.Errorf("aauth: retain MCP R3 document: %w", err)
	}
	return compact, nil
}

func (server *Server) parseMCPR3Operations(raw json.RawMessage) (r3.MCPOperationSet, error) {
	if server.mcpR3 == nil {
		return r3.MCPOperationSet{}, errors.New("aauth: request member \"r3_operations\" is not supported by this Resource")
	}
	var operations r3.MCPOperationSet
	if err := json.Unmarshal(raw, &operations); err != nil {
		return r3.MCPOperationSet{}, fmt.Errorf("aauth: invalid MCP r3_operations: %w", err)
	}
	if err := operations.ValidateKnownTools(server.mcpR3.knownTools); err != nil {
		return r3.MCPOperationSet{}, fmt.Errorf("aauth: invalid MCP r3_operations: %w", err)
	}
	return operations, nil
}

func mcpR3DocumentURI(issuer string, exactJSON []byte, personServer, accessServer string) string {
	return mcpR3DocumentURIFromDigest(issuer, r3.Digest(exactJSON), personServer, accessServer)
}

func mcpR3DocumentURIFromDigest(issuer, documentDigest, personServer, accessServer string) string {
	entitlementJSON, _ := json.Marshal([]string{"aauth-r3-entitlement-v1", personServer, accessServer})
	entitlementDigest := sha256.Sum256(entitlementJSON)
	return issuer + "/r3/" + documentDigest + "." + base64.RawURLEncoding.EncodeToString(entitlementDigest[:])
}

func (server *Server) serveMCPR3Document(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "private, no-store, no-transform")
	response.Header().Set("Vary", "Signature-Key, Signature-Input, Signature")
	if request.Method != http.MethodGet || request.URL.RawQuery != "" || request.URL.ForceQuery {
		response.WriteHeader(http.StatusNotFound)
		return
	}
	issuerURL, err := url.Parse(server.issuer)
	documentID := request.PathValue("document")
	exactPath := "/r3/" + documentID
	if err != nil || !strings.EqualFold(request.Host, issuerURL.Host) || request.URL.EscapedPath() != exactPath {
		response.WriteHeader(http.StatusNotFound)
		return
	}
	exactURI := server.issuer + exactPath
	prepared, err := signaturekey.PrepareRequest(request, server.clock, signaturekey.VerifyOptions{
		RequireExactComponents: true,
		AcceptedSchemes:        []signaturekey.Scheme{signaturekey.SchemeJWKSURI},
		MaxBodyBytes:           server.maxSignedBodyBytes,
	})
	if err != nil {
		writeProblem(response, http.StatusUnauthorized, "invalid_request", err)
		return
	}
	issuer, discoveryDocument, _, ok := prepared.Credential().JWKSURI()
	if !ok || discoveryDocument != aauth.PersonDiscoveryDocument && discoveryDocument != aauth.AccessDiscoveryDocument {
		response.WriteHeader(http.StatusNotFound)
		return
	}
	record, err := server.mcpR3.documents.Load(request.Context(), exactURI)
	if err != nil {
		if errors.Is(err, ErrR3DocumentNotFound) {
			response.WriteHeader(http.StatusNotFound)
			return
		}
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if !mcpR3DocumentEntitled(record, issuer, discoveryDocument) {
		response.WriteHeader(http.StatusNotFound)
		return
	}
	proof, err := prepared.VerifyJWKSURI(request.Context(), server.keyResolver)
	if err != nil {
		writeProblem(response, http.StatusUnauthorized, "invalid_request", err)
		return
	}
	if proof.Signer() != issuer {
		writeProblem(response, http.StatusUnauthorized, "invalid_request", errors.New("aauth: signed R3 document request signer does not match credential issuer"))
		return
	}
	if record.Reference.URI() != exactURI || record.PersonServer == "" || record.AccessServer == "" ||
		mcpR3DocumentURIFromDigest(server.issuer, record.Reference.Digest(), record.PersonServer, record.AccessServer) != exactURI {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("aauth: retained R3 document context is invalid"))
		return
	}
	if _, err := r3.ParseReferencedDocument(record.Reference, record.ExactJSON); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", fmt.Errorf("aauth: retained R3 document: %w", err))
		return
	}

	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Content-Length", strconv.Itoa(len(record.ExactJSON)))
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(record.ExactJSON)
}

func mcpR3DocumentEntitled(record R3DocumentRecord, issuer, discoveryDocument string) bool {
	return issuer == record.PersonServer && discoveryDocument == aauth.PersonDiscoveryDocument ||
		issuer == record.AccessServer && discoveryDocument == aauth.AccessDiscoveryDocument
}

func (server *Server) verifyPreparedMCPR3AuthRequest(
	request *http.Request,
	prepared signaturekey.PreparedRequest,
	compact string,
) (signaturekey.VerifiedRequest, aauth.AuthTokenClaims, r3.Reference, r3.GrantedOperations, error) {
	verificationClock := aauth.ClockFunc(func() time.Time { return prepared.VerifiedAt() })
	claims, reference, granted, err := r3.VerifyMCPDirectAuthToken(
		request.Context(), compact, server.keyResolver, verificationClock,
	)
	if err != nil {
		return signaturekey.VerifiedRequest{}, aauth.AuthTokenClaims{}, r3.Reference{}, r3.GrantedOperations{}, &requestTokenError{cause: err}
	}
	proof, err := prepared.Verify(claims.Confirmation.JWK)
	return proof, claims, reference, granted, err
}

func (server *Server) mcpR3OperationForRequest(request *http.Request) (r3.MCPOperation, bool, error) {
	if server.mcpR3 == nil {
		return r3.MCPOperation{}, false, nil
	}
	policyRequest, finish, err := cloneScopePolicyRequest(request)
	if err != nil {
		return r3.MCPOperation{}, false, fmt.Errorf("aauth: prepare MCP route policy request: %w", err)
	}
	tool, mapped, policyErr := server.mcpR3.operationForRequest(policyRequest)
	finishErr := finish()
	if err := errors.Join(policyErr, finishErr); err != nil {
		return r3.MCPOperation{}, false, fmt.Errorf("aauth: MCP route policy: %w", err)
	}
	if !mapped {
		if tool != "" {
			return r3.MCPOperation{}, false, errors.New("aauth: unmapped MCP route returned a tool")
		}
		return r3.MCPOperation{}, false, nil
	}
	operation, err := r3.NewMCPOperation(tool)
	if err != nil {
		return r3.MCPOperation{}, false, fmt.Errorf("aauth: MCP route operation: %w", err)
	}
	operationSet, err := r3.NewMCPOperationSet(operation)
	if err != nil {
		return r3.MCPOperation{}, false, err
	}
	if err := operationSet.ValidateKnownTools(server.mcpR3.knownTools); err != nil {
		return r3.MCPOperation{}, false, fmt.Errorf("aauth: MCP route operation: %w", err)
	}
	return operation, true, nil
}

func (server *Server) validateMCPR3ProtectedReference(
	authorization mcpR3ProtectedAuthorization,
	claims aauth.AuthTokenClaims,
) error {
	expected := mcpR3DocumentURIFromDigest(
		server.issuer,
		authorization.reference.Digest(),
		claims.PersonServer,
		claims.Issuer,
	)
	if authorization.reference.URI() != expected {
		return errors.New("aauth: MCP R3 reference does not match this Resource and token entitlement")
	}
	return nil
}

type mcpR3Config struct {
	discoveryEndpoint    string
	knownTools           []string
	documents            R3DocumentStore
	displayForOperations func(context.Context, r3.MCPOperationSet, *string) (*r3.Display, error)
	operationForRequest  func(*http.Request) (string, bool, error)
}

func validateMCPR3Config(config *MCPR3Config) (*mcpR3Config, error) {
	if config == nil {
		return nil, nil
	}
	if err := aauth.ValidateEndpoint(config.DiscoveryEndpoint); err != nil {
		return nil, fmt.Errorf("aauth: Resource MCP R3 discovery endpoint: %w", err)
	}
	if config.Documents == nil {
		return nil, errors.New("aauth: Resource MCP R3 document store is required")
	}
	if config.OperationForRequest == nil {
		return nil, errors.New("aauth: Resource MCP R3 operation mapper is required")
	}
	operations := make([]r3.MCPOperation, len(config.KnownTools))
	for index, tool := range config.KnownTools {
		operation, err := r3.NewMCPOperation(tool)
		if err != nil {
			return nil, fmt.Errorf("aauth: Resource authoritative MCP tool %d: %w", index, err)
		}
		operations[index] = operation
	}
	if _, err := r3.NewMCPOperationSet(operations...); err != nil {
		return nil, fmt.Errorf("aauth: Resource authoritative MCP tools: %w", err)
	}
	return &mcpR3Config{
		discoveryEndpoint:    config.DiscoveryEndpoint,
		knownTools:           append([]string(nil), config.KnownTools...),
		documents:            config.Documents,
		displayForOperations: config.DisplayForOperations,
		operationForRequest:  config.OperationForRequest,
	}, nil
}
