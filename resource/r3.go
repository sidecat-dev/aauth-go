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

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// R3Config enables registered R3 authorization on an HTTP Resource. Class
// authorization composes with federated or Person-Server authorization;
// per-call authorization requires the federated composition. Operation,
// document, token, and proposal semantics remain vocabulary neutral; HTTP is
// the explicit protected-invocation binding used by Server. Core-only
// authorization remains available when r3_operations is absent.
type R3Config struct {
	// Registry is the immutable allowlist used for every operation-bearing R3
	// artifact and token claim.
	Registry r3.Registry
	// Definitions prevents accidental mixing of snapshots from different
	// parser registrations. The host remains responsible for choosing and
	// feeding a trustworthy parser.
	Definitions r3.DefinitionRegistry
	// Vocabularies are the Resource's simultaneously advertised definitions.
	Vocabularies []R3VocabularyConfig
	// Documents retains exact bytes and their PS/AS fetch entitlement.
	Documents R3DocumentStore
	// HTTP maps one protected HTTP request into the transport-neutral R3
	// invocation used by authorization and proposal matching.
	HTTP R3HTTPAdapter
	// PerCall enables proposal-specific authorization for operations carried in
	// r3_per_call.
	PerCall *R3PerCallConfig
}

// R3HTTPAdapter is the protected-call binding used by Server. It owns only
// HTTP request interpretation; R3 operation and parameter semantics remain in
// the registered vocabulary and r3.Invocation.
type R3HTTPAdapter struct {
	// OperationForRequest maps a protected request to one registered operation.
	// A false ok identifies a Core-only route.
	OperationForRequest func(*http.Request) (operation r3.Operation, ok bool, err error)
	// PresentParameters extracts concrete parameter values for one
	// already-matched per-call operation. It runs only after class lineage has
	// been verified and may run again for a baseline 401 retry. It must be a
	// deterministic function of only the supplied request and operation. Both
	// callbacks receive independent request views.
	PresentParameters func(*http.Request, r3.Operation) (map[string]r3.PresentedParameter, error)
}

// R3VocabularyConfig binds one parser-derived authoritative snapshot to an
// optional consent description policy.
type R3VocabularyConfig struct {
	// Definition was derived by a caller-selected parser from the source
	// advertised at its retained endpoint.
	Definition r3.AuthoritativeSnapshot
	// DisplayForOperations optionally describes the consequences of one
	// validated request for Person Server consent.
	DisplayForOperations func(
		context.Context,
		r3.OperationSet,
		*string,
	) (*r3.Display, error)
}

// R3PerCallConfig supplies Resource-owned proposal description plus the
// focused proposal and retry stores. DescribeCall may consult current
// Resource state because it runs only when creating a new proposal, but it
// receives the same immutable invocation later used for parameter matching.
type R3PerCallConfig struct {
	DescribeCall func(context.Context, r3.Invocation, *string) (R3CallDescription, error)
	Proposals    R3ProposalStore
	Retries      R3RetryStore
}

// R3CallDescription is the Resource's proposed representation and display
// for one concrete call. Parameters must match the exact presented values in
// the invocation before the proposal can be published.
type R3CallDescription struct {
	Parameters r3.Parameters
	Display    *r3.ProposalDisplay
}

type r3ProtectedAuthorization struct {
	reference  r3.Reference
	operations r3.AuthTokenOperations
}

func (server *Server) issueR3ResourceToken(
	ctx context.Context,
	claims aauth.ResourceTokenClaims,
	person aauth.PersonTokenClaims,
	operations r3.OperationSet,
) (string, error) {
	vocabulary, ok := server.r3.vocabularies[operations.Vocabulary()]
	if !ok {
		return "", fmt.Errorf("aauth: R3 vocabulary %q is not configured", operations.Vocabulary())
	}
	var display *r3.Display
	var err error
	if vocabulary.displayForOperations != nil {
		display, err = vocabulary.displayForOperations(
			ctx, operations, cloneAuthorizationAccount(claims.Account),
		)
		if err != nil {
			return "", fmt.Errorf("aauth: describe R3 operations: %w", err)
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
		return "", fmt.Errorf("aauth: serialize R3 document: %w", err)
	}
	documentURI := r3DocumentURI(server.issuer, exactJSON, claims.PersonServer, claims.Audience, claims.JTI)
	compact, reference, err := r3.MintResourceToken(server.r3.registry, server.signingKey, claims, documentURI, exactJSON)
	if err != nil {
		return "", err
	}
	authTokenIssuerDocument := aauth.AccessDiscoveryDocument
	if server.authorizationTopology == authorizationTopologyPersonServer {
		authTokenIssuerDocument = aauth.PersonDiscoveryDocument
	}
	record := R3DocumentRecord{
		Reference: reference, ExactJSON: append([]byte(nil), exactJSON...),
		PersonServer: claims.PersonServer, AuthTokenIssuer: claims.Audience,
		AuthTokenIssuerDocument: authTokenIssuerDocument,
		ClassContext: R3ClassAuthorizationContext{
			ExactResourceToken:   compact,
			ResourceToken:        claims,
			PersonTokenIssuedAt:  person.IssuedAt,
			PersonTokenNotBefore: person.NotBefore,
			PersonTokenExpiresAt: person.ExpiresAt,
		},
	}
	if err := server.r3.documents.Commit(ctx, record); err != nil {
		return "", fmt.Errorf("aauth: retain R3 document: %w", err)
	}
	return compact, nil
}

func (server *Server) parseR3Operations(raw json.RawMessage) (r3.OperationSet, error) {
	if server.r3 == nil {
		return r3.OperationSet{}, errors.New("aauth: request member \"r3_operations\" is not supported by this Resource")
	}
	operations, err := server.r3.registry.ParseOperationSet(raw)
	if err != nil {
		return r3.OperationSet{}, fmt.Errorf("aauth: invalid r3_operations: %w", err)
	}
	vocabulary, ok := server.r3.vocabularies[operations.Vocabulary()]
	if !ok {
		return r3.OperationSet{}, fmt.Errorf("aauth: R3 vocabulary %q is not configured", operations.Vocabulary())
	}
	if err := vocabulary.definition.ValidateDefined(operations); err != nil {
		return r3.OperationSet{}, fmt.Errorf("aauth: validate r3_operations: %w", err)
	}
	return operations, nil
}

func r3DocumentURI(issuer string, exactJSON []byte, personServer, authTokenIssuer, resourceTokenJTI string) string {
	return r3DocumentURIFromDigest(issuer, r3.Digest(exactJSON), personServer, authTokenIssuer, resourceTokenJTI)
}

func r3DocumentURIFromDigest(issuer, documentDigest, personServer, authTokenIssuer, resourceTokenJTI string) string {
	entitlementJSON, _ := json.Marshal([]string{"aauth-r3-entitlement-v1", personServer, authTokenIssuer})
	entitlementDigest := sha256.Sum256(entitlementJSON)
	lineageDigest := sha256.Sum256([]byte("aauth-r3-lineage-v1\x00" + resourceTokenJTI))
	return issuer + "/r3/c." + documentDigest + "." +
		base64.RawURLEncoding.EncodeToString(entitlementDigest[:]) + "." +
		base64.RawURLEncoding.EncodeToString(lineageDigest[:])
}

func r3ProposalURI(issuer string, exactJSON []byte, personServer, accessServer, resourceTokenJTI string) string {
	return r3ProposalURIFromDigest(issuer, r3.Digest(exactJSON), personServer, accessServer, resourceTokenJTI)
}

func r3ProposalURIFromDigest(issuer, proposalDigest, personServer, accessServer, resourceTokenJTI string) string {
	entitlementJSON, _ := json.Marshal([]string{"aauth-r3-entitlement-v1", personServer, accessServer})
	entitlementDigest := sha256.Sum256(entitlementJSON)
	lineageDigest := sha256.Sum256([]byte("aauth-r3-proposal-v1\x00" + resourceTokenJTI))
	return issuer + "/r3/p." + proposalDigest + "." +
		base64.RawURLEncoding.EncodeToString(entitlementDigest[:]) + "." +
		base64.RawURLEncoding.EncodeToString(lineageDigest[:])
}

func (server *Server) serveR3Document(response http.ResponseWriter, request *http.Request) {
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
	var personServer, authTokenIssuer, authTokenIssuerDocument string
	var validateArtifact func() error
	switch {
	case strings.HasPrefix(documentID, "c."):
		record, err := server.r3.documents.Load(request.Context(), exactURI)
		if err != nil {
			if errors.Is(err, ErrR3DocumentNotFound) {
				response.WriteHeader(http.StatusNotFound)
				return
			}
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		exactJSON, personServer, authTokenIssuer = record.ExactJSON, record.PersonServer, record.AuthTokenIssuer
		authTokenIssuerDocument = record.AuthTokenIssuerDocument
		validateArtifact = func() error {
			if record.Reference.URI() != exactURI || record.PersonServer == "" || record.AuthTokenIssuer == "" ||
				!validR3ClassContext(record) ||
				r3DocumentURIFromDigest(
					server.issuer, record.Reference.Digest(), record.PersonServer, record.AuthTokenIssuer,
					record.ClassContext.ResourceToken.JTI,
				) != exactURI {
				return errors.New("aauth: retained R3 class context is invalid")
			}
			document, err := server.r3.registry.ParseReferencedDocument(record.Reference, record.ExactJSON)
			if err != nil {
				return fmt.Errorf("aauth: retained R3 class document: %w", err)
			}
			if err := r3.ValidateDocumentAccount(document, record.ClassContext.ResourceToken.Account); err != nil {
				return fmt.Errorf("aauth: retained R3 class account: %w", err)
			}
			return nil
		}
	case strings.HasPrefix(documentID, "p."):
		if server.r3.perCall == nil {
			response.WriteHeader(http.StatusNotFound)
			return
		}
		record, err := server.r3.perCall.proposals.Load(request.Context(), exactURI)
		if err != nil {
			if errors.Is(err, ErrR3ProposalNotFound) {
				response.WriteHeader(http.StatusNotFound)
				return
			}
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		exactJSON, personServer, authTokenIssuer = record.ExactJSON, record.PersonServer, record.AccessServer
		authTokenIssuerDocument = aauth.AccessDiscoveryDocument
		validateArtifact = func() error {
			if record.Reference.URI() != exactURI || record.PersonServer == "" || record.AccessServer == "" ||
				record.ResourceTokenJTI == "" ||
				r3ProposalURIFromDigest(
					server.issuer, record.Reference.Digest(), record.PersonServer, record.AccessServer, record.ResourceTokenJTI,
				) != exactURI {
				return errors.New("aauth: retained R3 proposal context is invalid")
			}
			if _, err := server.r3.registry.ParseReferencedProposal(record.Reference, record.ExactJSON); err != nil {
				return fmt.Errorf("aauth: retained R3 proposal: %w", err)
			}
			return nil
		}
	default:
		response.WriteHeader(http.StatusNotFound)
		return
	}
	if !r3FetchEntitled(personServer, authTokenIssuer, authTokenIssuerDocument, issuer, discoveryDocument) {
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
		claims.Audience != record.AuthTokenIssuer || claims.PresentedJTI == "" ||
		claims.IssuedAt <= 0 || claims.ExpiresAt <= claims.IssuedAt ||
		record.ClassContext.PersonTokenIssuedAt <= 0 ||
		record.ClassContext.PersonTokenExpiresAt <= record.ClassContext.PersonTokenIssuedAt {
		return false
	}
	if record.AuthTokenIssuerDocument != aauth.PersonDiscoveryDocument &&
		record.AuthTokenIssuerDocument != aauth.AccessDiscoveryDocument {
		return false
	}
	if record.ClassContext.PersonTokenNotBefore < 0 ||
		record.ClassContext.PersonTokenNotBefore >= record.ClassContext.PersonTokenExpiresAt {
		return false
	}
	return strings.HasPrefix(record.Reference.URI(), claims.Issuer+"/r3/")
}

func r3FetchEntitled(personServer, authTokenIssuer, authTokenIssuerDocument, issuer, discoveryDocument string) bool {
	return issuer == personServer && discoveryDocument == aauth.PersonDiscoveryDocument ||
		issuer == authTokenIssuer && discoveryDocument == authTokenIssuerDocument
}

func (server *Server) verifyPreparedR3AuthRequest(
	request *http.Request,
	prepared signaturekey.PreparedRequest,
	compact string,
) (signaturekey.VerifiedRequest, aauth.AuthTokenClaims, r3.Reference, r3.AuthTokenOperations, error) {
	verificationClock := aauth.ClockFunc(func() time.Time { return prepared.VerifiedAt() })
	claims, reference, operations, err := r3.VerifyAuthTokenClaims(
		request.Context(), server.r3.registry, compact, server.keyResolver, verificationClock,
	)
	if err != nil {
		return signaturekey.VerifiedRequest{}, aauth.AuthTokenClaims{}, r3.Reference{}, r3.AuthTokenOperations{}, &requestTokenError{cause: err}
	}
	proof, err := prepared.Verify(claims.Confirmation.JWK)
	return proof, claims, reference, operations, err
}

type r3ReferenceKind uint8

const (
	r3ClassReference r3ReferenceKind = iota + 1
	r3ProposalReference
)

func (server *Server) validateR3ProtectedReference(
	authorization r3ProtectedAuthorization,
	claims aauth.AuthTokenClaims,
) (r3ReferenceKind, error) {
	for _, candidate := range []struct {
		kind   r3ReferenceKind
		prefix string
	}{
		{r3ClassReference, "c."},
		{r3ProposalReference, "p."},
	} {
		if r3ReferenceMatchesResource(
			server.issuer, authorization.reference, claims.PersonServer, claims.Issuer, candidate.prefix,
		) {
			return candidate.kind, nil
		}
	}
	return 0, errors.New("aauth: R3 reference does not match this Resource and token entitlement")
}

func r3ReferenceMatchesResource(issuer string, reference r3.Reference, personServer, accessServer, kindPrefix string) bool {
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

type r3Config struct {
	registry        r3.Registry
	vocabularies    map[r3.VocabularyURI]r3VocabularyConfig
	vocabularyOrder []r3.VocabularyURI
	documents       R3DocumentStore
	http            R3HTTPAdapter
	perCall         *r3PerCallConfig
}

func (server *Server) r3OperationForRequest(request *http.Request) (r3.Operation, bool, error) {
	if server.r3 == nil {
		return r3.Operation{}, false, nil
	}
	policyRequest, finish, err := cloneScopePolicyRequest(request)
	if err != nil {
		return r3.Operation{}, false, fmt.Errorf("aauth: prepare R3 route policy request: %w", err)
	}
	operation, mapped, policyErr := server.r3.http.OperationForRequest(policyRequest)
	if err := errors.Join(policyErr, finish()); err != nil {
		return r3.Operation{}, false, fmt.Errorf("aauth: R3 route policy: %w", err)
	}
	if !mapped {
		if operation.JSON() != nil {
			return r3.Operation{}, false, errors.New("aauth: unmapped R3 route returned an operation")
		}
		return r3.Operation{}, false, nil
	}
	if operation.JSON() == nil {
		return r3.Operation{}, false, errors.New("aauth: mapped R3 route returned an invalid operation")
	}
	operationSet, err := r3.NewOperationSet(operation)
	if err != nil {
		return r3.Operation{}, false, err
	}
	vocabulary, ok := server.r3.vocabularies[operation.Vocabulary()]
	if !ok {
		return r3.Operation{}, false, fmt.Errorf("aauth: mapped R3 vocabulary %q is not configured", operation.Vocabulary())
	}
	if err := vocabulary.definition.ValidateDefined(operationSet); err != nil {
		return r3.Operation{}, false, fmt.Errorf("aauth: validate mapped R3 operation: %w", err)
	}
	return operation, true, nil
}

func (server *Server) r3InvocationForRequest(request *http.Request, operation r3.Operation) (r3.Invocation, error) {
	policyRequest, finish, err := cloneScopePolicyRequest(request)
	if err != nil {
		return r3.Invocation{}, fmt.Errorf("aauth: prepare R3 invocation request: %w", err)
	}
	parameters, presentErr := server.r3.http.PresentParameters(policyRequest, operation)
	if err := errors.Join(presentErr, finish()); err != nil {
		return r3.Invocation{}, fmt.Errorf("aauth: R3 invocation adapter: %w", err)
	}
	invocation, err := r3.NewInvocation(operation, parameters)
	if err != nil {
		return r3.Invocation{}, fmt.Errorf("aauth: R3 invocation adapter: %w", err)
	}
	return invocation, nil
}

type r3VocabularyConfig struct {
	definition           r3.AuthoritativeSnapshot
	displayForOperations func(context.Context, r3.OperationSet, *string) (*r3.Display, error)
}

type r3PerCallConfig struct {
	describeCall func(context.Context, r3.Invocation, *string) (R3CallDescription, error)
	proposals    R3ProposalStore
	retries      R3RetryStore
}

func validateR3Config(config *R3Config) (*r3Config, error) {
	if config == nil {
		return nil, nil
	}
	if config.Registry.Len() == 0 {
		return nil, errors.New("aauth: Resource R3 vocabulary registry is required")
	}
	if config.Definitions.Len() == 0 {
		return nil, errors.New("aauth: Resource R3 definition registry is required")
	}
	if len(config.Vocabularies) == 0 {
		return nil, errors.New("aauth: Resource requires at least one R3 vocabulary")
	}
	if config.Documents == nil {
		return nil, errors.New("aauth: Resource R3 document store is required")
	}
	if config.HTTP.OperationForRequest == nil {
		return nil, errors.New("aauth: Resource R3 HTTP operation adapter is required")
	}
	vocabularies := make(map[r3.VocabularyURI]r3VocabularyConfig, len(config.Vocabularies))
	order := make([]r3.VocabularyURI, len(config.Vocabularies))
	for index, candidate := range config.Vocabularies {
		if err := config.Definitions.Validate(candidate.Definition); err != nil {
			return nil, fmt.Errorf("aauth: Resource R3 authoritative definition: %w", err)
		}
		operations := candidate.Definition.Operations()
		if err := config.Registry.ValidateOperationSet(operations); err != nil {
			return nil, fmt.Errorf("aauth: Resource R3 authoritative definition operations: %w", err)
		}
		uri := candidate.Definition.Vocabulary()
		if _, duplicate := vocabularies[uri]; duplicate {
			return nil, fmt.Errorf("aauth: duplicate Resource R3 vocabulary %q", uri)
		}
		known := operations.Operations()
		if len(known) == 0 {
			return nil, fmt.Errorf("aauth: Resource R3 vocabulary %q requires authoritative operations", uri)
		}
		for operationIndex, operation := range known {
			if operation.JSON() == nil {
				return nil, fmt.Errorf("aauth: Resource R3 vocabulary %q operation %d is invalid", uri, operationIndex)
			}
			hints, present, err := candidate.Definition.HintsFor(operation)
			if err != nil {
				return nil, fmt.Errorf("aauth: Resource R3 vocabulary %q operation %d hints: %w", uri, operationIndex, err)
			}
			if present {
				if err := hints.ValidateForPublication(); err != nil {
					return nil, fmt.Errorf("aauth: Resource R3 vocabulary %q operation %d publication: %w", uri, operationIndex, err)
				}
			}
		}
		vocabularies[uri] = r3VocabularyConfig{
			definition:           candidate.Definition,
			displayForOperations: candidate.DisplayForOperations,
		}
		order[index] = uri
	}
	var perCall *r3PerCallConfig
	if config.PerCall != nil {
		if config.HTTP.PresentParameters == nil {
			return nil, errors.New("aauth: Resource R3 HTTP parameter adapter is required for per-call authorization")
		}
		if config.PerCall.DescribeCall == nil {
			return nil, errors.New("aauth: Resource R3 per-call description adapter is required")
		}
		if config.PerCall.Proposals == nil {
			return nil, errors.New("aauth: Resource R3 proposal store is required")
		}
		if config.PerCall.Retries == nil {
			return nil, errors.New("aauth: Resource R3 retry store is required")
		}
		perCall = &r3PerCallConfig{
			describeCall: config.PerCall.DescribeCall,
			proposals:    config.PerCall.Proposals,
			retries:      config.PerCall.Retries,
		}
	}
	return &r3Config{
		registry: config.Registry, vocabularies: vocabularies,
		vocabularyOrder: order, documents: config.Documents,
		http: config.HTTP, perCall: perCall,
	}, nil
}
