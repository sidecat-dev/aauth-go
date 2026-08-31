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
	// PerCall enables proposal-specific authorization for operations carried in
	// r3_per_call.
	PerCall *MCPR3PerCallConfig
}

// MCPR3PerCallConfig supplies separate Resource-owned parameter extraction
// and proposal-description adapters plus the focused proposal and retry
// stores. PresentCall must depend only on the concrete request; it is reused
// after approval and on retained-result replay. DescribeCall may consult
// current Resource state because it runs only when creating a new proposal.
type MCPR3PerCallConfig struct {
	PresentCall  func(context.Context, *http.Request, r3.MCPOperation, *string) (map[string]r3.PresentedMCPParameter, error)
	DescribeCall func(context.Context, *http.Request, r3.MCPOperation, *string) (MCPR3CallDescription, error)
	Proposals    R3ProposalStore
	Retries      R3RetryStore
}

// MCPR3CallDescription is the Resource's proposed representation and display
// for one concrete call. The separate PresentCall adapter supplies the exact
// call-time values used to verify Parameters before publication.
type MCPR3CallDescription struct {
	Parameters r3.MCPParameters
	Display    *r3.ProposalDisplay
}

type mcpR3ProtectedAuthorization struct {
	reference  r3.Reference
	operations r3.AuthTokenOperations
}

func (server *Server) issueMCPR3ResourceToken(
	ctx context.Context,
	claims aauth.ResourceTokenClaims,
	person aauth.PersonTokenClaims,
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
	documentURI := mcpR3DocumentURI(server.issuer, exactJSON, claims.PersonServer, claims.Audience, claims.JTI)
	compact, reference, err := r3.MintMCPResourceToken(server.signingKey, claims, documentURI, exactJSON)
	if err != nil {
		return "", err
	}
	record := R3DocumentRecord{
		Reference: reference, ExactJSON: append([]byte(nil), exactJSON...),
		PersonServer: claims.PersonServer, AccessServer: claims.Audience,
		ClassContext: R3ClassAuthorizationContext{
			ExactResourceToken:   compact,
			ResourceToken:        claims,
			PersonTokenIssuedAt:  person.IssuedAt,
			PersonTokenNotBefore: person.NotBefore,
			PersonTokenExpiresAt: person.ExpiresAt,
		},
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

func mcpR3DocumentURI(issuer string, exactJSON []byte, personServer, accessServer, resourceTokenJTI string) string {
	return mcpR3DocumentURIFromDigest(issuer, r3.Digest(exactJSON), personServer, accessServer, resourceTokenJTI)
}

func mcpR3DocumentURIFromDigest(issuer, documentDigest, personServer, accessServer, resourceTokenJTI string) string {
	entitlementJSON, _ := json.Marshal([]string{"aauth-r3-entitlement-v1", personServer, accessServer})
	entitlementDigest := sha256.Sum256(entitlementJSON)
	lineageDigest := sha256.Sum256([]byte("aauth-r3-lineage-v1\x00" + resourceTokenJTI))
	return issuer + "/r3/c." + documentDigest + "." +
		base64.RawURLEncoding.EncodeToString(entitlementDigest[:]) + "." +
		base64.RawURLEncoding.EncodeToString(lineageDigest[:])
}

func mcpR3ProposalURI(issuer string, exactJSON []byte, personServer, accessServer, resourceTokenJTI string) string {
	return mcpR3ProposalURIFromDigest(issuer, r3.Digest(exactJSON), personServer, accessServer, resourceTokenJTI)
}

func mcpR3ProposalURIFromDigest(issuer, proposalDigest, personServer, accessServer, resourceTokenJTI string) string {
	entitlementJSON, _ := json.Marshal([]string{"aauth-r3-entitlement-v1", personServer, accessServer})
	entitlementDigest := sha256.Sum256(entitlementJSON)
	lineageDigest := sha256.Sum256([]byte("aauth-r3-proposal-v1\x00" + resourceTokenJTI))
	return issuer + "/r3/p." + proposalDigest + "." +
		base64.RawURLEncoding.EncodeToString(entitlementDigest[:]) + "." +
		base64.RawURLEncoding.EncodeToString(lineageDigest[:])
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
	var exactJSON []byte
	var personServer, accessServer string
	var validateArtifact func() error
	switch {
	case strings.HasPrefix(documentID, "c."):
		record, err := server.mcpR3.documents.Load(request.Context(), exactURI)
		if err != nil {
			if errors.Is(err, ErrR3DocumentNotFound) {
				response.WriteHeader(http.StatusNotFound)
				return
			}
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		exactJSON, personServer, accessServer = record.ExactJSON, record.PersonServer, record.AccessServer
		validateArtifact = func() error {
			if record.Reference.URI() != exactURI || record.PersonServer == "" || record.AccessServer == "" ||
				!validR3ClassContext(record) ||
				mcpR3DocumentURIFromDigest(
					server.issuer, record.Reference.Digest(), record.PersonServer, record.AccessServer,
					record.ClassContext.ResourceToken.JTI,
				) != exactURI {
				return errors.New("aauth: retained R3 class context is invalid")
			}
			document, err := r3.ParseReferencedDocument(record.Reference, record.ExactJSON)
			if err != nil {
				return fmt.Errorf("aauth: retained R3 class document: %w", err)
			}
			if err := r3.ValidateDocumentAccount(document, record.ClassContext.ResourceToken.Account); err != nil {
				return fmt.Errorf("aauth: retained R3 class account: %w", err)
			}
			return nil
		}
	case strings.HasPrefix(documentID, "p."):
		if server.mcpR3.perCall == nil {
			response.WriteHeader(http.StatusNotFound)
			return
		}
		record, err := server.mcpR3.perCall.proposals.Load(request.Context(), exactURI)
		if err != nil {
			if errors.Is(err, ErrR3ProposalNotFound) {
				response.WriteHeader(http.StatusNotFound)
				return
			}
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		exactJSON, personServer, accessServer = record.ExactJSON, record.PersonServer, record.AccessServer
		validateArtifact = func() error {
			if record.Reference.URI() != exactURI || record.PersonServer == "" || record.AccessServer == "" ||
				record.ResourceTokenJTI == "" ||
				mcpR3ProposalURIFromDigest(
					server.issuer, record.Reference.Digest(), record.PersonServer, record.AccessServer, record.ResourceTokenJTI,
				) != exactURI {
				return errors.New("aauth: retained R3 proposal context is invalid")
			}
			if _, err := r3.ParseReferencedProposal(record.Reference, record.ExactJSON); err != nil {
				return fmt.Errorf("aauth: retained R3 proposal: %w", err)
			}
			return nil
		}
	default:
		response.WriteHeader(http.StatusNotFound)
		return
	}
	if !mcpR3FetchEntitled(personServer, accessServer, issuer, discoveryDocument) {
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
	if err := validateArtifact(); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Content-Length", strconv.Itoa(len(exactJSON)))
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(exactJSON)
}

func validR3ClassContext(record R3DocumentRecord) bool {
	claims := record.ClassContext.ResourceToken
	if claims.Issuer == "" || claims.JTI == "" || claims.PersonServer != record.PersonServer ||
		claims.Audience != record.AccessServer || claims.PresentedJTI == "" ||
		claims.IssuedAt <= 0 || claims.ExpiresAt <= claims.IssuedAt ||
		record.ClassContext.PersonTokenIssuedAt <= 0 ||
		record.ClassContext.PersonTokenExpiresAt <= record.ClassContext.PersonTokenIssuedAt {
		return false
	}
	if record.ClassContext.PersonTokenNotBefore < 0 ||
		record.ClassContext.PersonTokenNotBefore >= record.ClassContext.PersonTokenExpiresAt {
		return false
	}
	return strings.HasPrefix(record.Reference.URI(), claims.Issuer+"/r3/")
}

func mcpR3FetchEntitled(personServer, accessServer, issuer, discoveryDocument string) bool {
	return issuer == personServer && discoveryDocument == aauth.PersonDiscoveryDocument ||
		issuer == accessServer && discoveryDocument == aauth.AccessDiscoveryDocument
}

func (server *Server) verifyPreparedMCPR3AuthRequest(
	request *http.Request,
	prepared signaturekey.PreparedRequest,
	compact string,
) (signaturekey.VerifiedRequest, aauth.AuthTokenClaims, r3.Reference, r3.AuthTokenOperations, error) {
	verificationClock := aauth.ClockFunc(func() time.Time { return prepared.VerifiedAt() })
	claims, reference, operations, err := r3.VerifyMCPAuthTokenClaims(
		request.Context(), compact, server.keyResolver, verificationClock,
	)
	if err != nil {
		return signaturekey.VerifiedRequest{}, aauth.AuthTokenClaims{}, r3.Reference{}, r3.AuthTokenOperations{}, &requestTokenError{cause: err}
	}
	proof, err := prepared.Verify(claims.Confirmation.JWK)
	return proof, claims, reference, operations, err
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

type mcpR3ReferenceKind uint8

const (
	mcpR3ClassReference mcpR3ReferenceKind = iota + 1
	mcpR3ProposalReference
)

func (server *Server) validateMCPR3ProtectedReference(
	authorization mcpR3ProtectedAuthorization,
	claims aauth.AuthTokenClaims,
) (mcpR3ReferenceKind, error) {
	for _, candidate := range []struct {
		kind   mcpR3ReferenceKind
		prefix string
	}{
		{mcpR3ClassReference, "c."},
		{mcpR3ProposalReference, "p."},
	} {
		if mcpR3ReferenceMatchesResource(
			server.issuer, authorization.reference, claims.PersonServer, claims.Issuer, candidate.prefix,
		) {
			return candidate.kind, nil
		}
	}
	return 0, errors.New("aauth: MCP R3 reference does not match this Resource and token entitlement")
}

func mcpR3ReferenceMatchesResource(issuer string, reference r3.Reference, personServer, accessServer, kindPrefix string) bool {
	entitlementJSON, _ := json.Marshal([]string{"aauth-r3-entitlement-v1", personServer, accessServer})
	entitlementDigest := sha256.Sum256(entitlementJSON)
	prefix := issuer + "/r3/" + kindPrefix + reference.Digest() + "." + base64.RawURLEncoding.EncodeToString(entitlementDigest[:]) + "."
	if !strings.HasPrefix(reference.URI(), prefix) {
		return false
	}
	lineage := strings.TrimPrefix(reference.URI(), prefix)
	decoded, err := base64.RawURLEncoding.DecodeString(lineage)
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == lineage
}

type mcpR3Config struct {
	discoveryEndpoint    string
	knownTools           []string
	documents            R3DocumentStore
	displayForOperations func(context.Context, r3.MCPOperationSet, *string) (*r3.Display, error)
	operationForRequest  func(*http.Request) (string, bool, error)
	perCall              *mcpR3PerCallConfig
}

type mcpR3PerCallConfig struct {
	presentCall  func(context.Context, *http.Request, r3.MCPOperation, *string) (map[string]r3.PresentedMCPParameter, error)
	describeCall func(context.Context, *http.Request, r3.MCPOperation, *string) (MCPR3CallDescription, error)
	proposals    R3ProposalStore
	retries      R3RetryStore
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
	var perCall *mcpR3PerCallConfig
	if config.PerCall != nil {
		if config.PerCall.PresentCall == nil {
			return nil, errors.New("aauth: Resource MCP R3 per-call parameter adapter is required")
		}
		if config.PerCall.DescribeCall == nil {
			return nil, errors.New("aauth: Resource MCP R3 per-call description adapter is required")
		}
		if config.PerCall.Proposals == nil {
			return nil, errors.New("aauth: Resource MCP R3 proposal store is required")
		}
		if config.PerCall.Retries == nil {
			return nil, errors.New("aauth: Resource MCP R3 retry store is required")
		}
		perCall = &mcpR3PerCallConfig{
			presentCall:  config.PerCall.PresentCall,
			describeCall: config.PerCall.DescribeCall,
			proposals:    config.PerCall.Proposals,
			retries:      config.PerCall.Retries,
		}
	}
	return &mcpR3Config{
		discoveryEndpoint:    config.DiscoveryEndpoint,
		knownTools:           append([]string(nil), config.KnownTools...),
		documents:            config.Documents,
		displayForOperations: config.DisplayForOperations,
		operationForRequest:  config.OperationForRequest,
		perCall:              perCall,
	}, nil
}
