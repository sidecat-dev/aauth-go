package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/sourcecoverage"
	"gitlab.com/sidecat-dev/aauth-go/reference"
)

const (
	personProfileFormat      = "aauth.reference.person-profile.v0"
	personReadyFormat        = "aauth.reference.person-ready.v0"
	maximumProfileSize       = 1 << 20
	maximumTLSIdentitySize   = 1 << 20
	personShutdownTimeout    = 5 * time.Second
	personReadHeaderTimeout  = 5 * time.Second
	personReadTimeout        = 30 * time.Second
	personWriteTimeout       = 30 * time.Second
	personIdleTimeout        = 60 * time.Second
	personMaximumHeaderBytes = 64 << 10
	coverageVerifiedFormat   = "aauth.source-coverage-verification.v0"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) >= 2 {
		switch {
		case args[0] == "verify" && args[1] == "coverage":
			return runCoverageVerification(args[2:], stdout, stderr)
		case args[0] == "diagnose" && args[1] == "person":
			return runPersonDiagnosis(args[2:], stdout, stderr)
		case args[0] == "demo" && args[1] == "person":
			return runPersonDemo(args[2:], stdout, stderr)
		case args[0] == "serve" && args[1] == "person":
			return runPersonServer(args[2:], stdout, stderr)
		}
	}
	writeUsage(stderr)
	return 2
}

func runPersonServer(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("serve person", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	profilePath := flags.String("profile", "", "protected person-server profile")
	if err := flags.Parse(args); err != nil ||
		flags.NArg() != 0 ||
		strings.TrimSpace(*profilePath) != *profilePath ||
		*profilePath == "" {
		writeUsage(stderr)
		return 2
	}
	if err := servePerson(*profilePath, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "aauth-reference: person server failed: %v\n", err)
		return 1
	}
	return 0
}

func writeUsage(writer io.Writer) {
	fmt.Fprintln(writer, "Usage:")
	fmt.Fprintln(writer, "  aauth-reference serve person --profile FILE")
	fmt.Fprintln(writer, "  aauth-reference diagnose person --profile FILE")
	fmt.Fprintln(writer, "  aauth-reference demo person")
	fmt.Fprintln(
		writer,
		"  aauth-reference verify coverage [--source-dir DIR] [--repo DIR]",
	)
}

type coverageVerification struct {
	Schema       string `json:"schema"`
	Profile      string `json:"profile"`
	SourceCount  int    `json:"source_count"`
	SectionCount int    `json:"section_count"`
	Status       string `json:"status"`
}

func runCoverageVerification(
	args []string,
	stdout io.Writer,
	stderr io.Writer,
) int {
	flags := flag.NewFlagSet("verify coverage", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	sourceDir := flags.String(
		"source-dir",
		"",
		"directory containing pinned sources (default: the retained repository copies)",
	)
	repoDir := flags.String("repo", ".", "aauth-go repository root")
	if err := flags.Parse(args); err != nil ||
		flags.NArg() != 0 ||
		strings.TrimSpace(*sourceDir) != *sourceDir ||
		strings.TrimSpace(*repoDir) != *repoDir ||
		*repoDir == "" {
		writeUsage(stderr)
		return 2
	}
	if *sourceDir == "" {
		*sourceDir = filepath.Join(*repoDir, "internal", "sourcecoverage", "sources")
	}
	bundle, err := sourcecoverage.Embedded()
	if err != nil {
		fmt.Fprintln(stderr, "aauth-reference: embedded coverage data is invalid")
		return 1
	}
	if err := bundle.VerifySources(*sourceDir); err != nil {
		fmt.Fprintln(stderr, "aauth-reference: pinned sources do not verify")
		return 1
	}
	if err := bundle.VerifyEvidence(*repoDir); err != nil {
		fmt.Fprintln(stderr, "aauth-reference: implementation evidence does not verify")
		return 1
	}
	sectionCount := 0
	for _, source := range bundle.Inventory.Sources {
		sectionCount += len(source.Sections)
	}
	body, err := json.Marshal(coverageVerification{
		Schema:       coverageVerifiedFormat,
		Profile:      bundle.Manifest.Profile,
		SourceCount:  len(bundle.Manifest.Sources),
		SectionCount: sectionCount,
		Status:       "verified",
	})
	if err != nil {
		fmt.Fprintln(stderr, "aauth-reference: encode coverage result")
		return 1
	}
	if _, err := fmt.Fprintln(stdout, string(body)); err != nil {
		fmt.Fprintln(stderr, "aauth-reference: publish coverage result")
		return 1
	}
	return 0
}

type personProfile struct {
	Format          string                `json:"format"`
	Identifier      string                `json:"identifier"`
	Listen          string                `json:"listen"`
	KeyID           string                `json:"key_id"`
	SigningKey      []byte                `json:"signing_key"`
	TLSCertificate  string                `json:"tls_certificate"`
	TLSPrivateKey   string                `json:"tls_private_key"`
	GovernanceFile  string                `json:"governance_file"`
	TrustedKeys     map[string][]jose.JWK `json:"trusted_keys"`
	AllowedActions  []string              `json:"allowed_actions"`
	AllowedScopes   []string              `json:"allowed_scopes,omitempty"`
	PendingLifetime int64                 `json:"pending_lifetime_seconds,omitempty"`
}

type personReady struct {
	Schema     string `json:"schema"`
	Identifier string `json:"identifier"`
	Listen     string `json:"listen"`
}

type personDeployment struct {
	profile            personProfile
	server             *reference.PersonServer
	tlsConfig          *tls.Config
	signer             *protectedSigner
	authorizationStore *reference.FileAuthorizationStateStore
	publicKey          jose.JWK
	tlsLeaf            *x509.Certificate
}

func servePerson(profilePath string, stdout io.Writer, stderr io.Writer) error {
	deployment, err := loadPersonDeployment(profilePath)
	if err != nil {
		return err
	}
	defer deployment.close()

	listener, err := net.Listen("tcp", deployment.profile.Listen)
	if err != nil {
		return errors.New("listen address is unavailable")
	}
	tlsListener := tls.NewListener(listener, deployment.tlsConfig)
	httpServer := &http.Server{
		Handler:           deployment.server.Handler(),
		ReadHeaderTimeout: personReadHeaderTimeout,
		ReadTimeout:       personReadTimeout,
		WriteTimeout:      personWriteTimeout,
		IdleTimeout:       personIdleTimeout,
		MaxHeaderBytes:    personMaximumHeaderBytes,
		ErrorLog:          log.New(stderr, "aauth-reference: ", 0),
	}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- httpServer.Serve(tlsListener)
	}()
	readyBody, err := json.Marshal(personReady{
		Schema:     personReadyFormat,
		Identifier: deployment.profile.Identifier,
		Listen:     listener.Addr().String(),
	})
	if err != nil {
		_ = httpServer.Close()
		<-serveErr
		return errors.New("encode readiness")
	}
	if _, err := fmt.Fprintln(stdout, string(readyBody)); err != nil {
		_ = httpServer.Close()
		<-serveErr
		return errors.New("publish readiness")
	}

	signalContext, stopSignals := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stopSignals()
	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("person HTTPS server stopped")
	case <-signalContext.Done():
	}
	shutdownContext, cancel := context.WithTimeout(
		context.Background(),
		personShutdownTimeout,
	)
	defer cancel()
	if err := httpServer.Shutdown(shutdownContext); err != nil {
		_ = httpServer.Close()
		return errors.New("person HTTPS server shutdown failed")
	}
	if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return errors.New("person HTTPS server stopped")
	}
	return nil
}

func loadPersonDeployment(profilePath string) (*personDeployment, error) {
	body, err := readProtectedFile(profilePath, maximumProfileSize)
	if err != nil {
		return nil, errors.New("profile must be an owned unaliased 0600 file")
	}
	defer clearBytes(body)
	var profile personProfile
	if err := unmarshalSingleJSON(body, &profile); err != nil {
		return nil, errors.New("profile is invalid JSON")
	}
	defer clearBytes(profile.SigningKey)
	if err := validatePersonProfile(profile); err != nil {
		return nil, err
	}
	signer, err := newProtectedSigner(profile.SigningKey)
	if err != nil {
		return nil, err
	}
	signingKey, err := jose.NewSigningKey(profile.KeyID, signer)
	if err != nil {
		_ = signer.Close()
		return nil, errors.New("profile signing identity is invalid")
	}
	certificateBody, err := readProtectedFile(
		profile.TLSCertificate,
		maximumTLSIdentitySize,
	)
	if err != nil {
		_ = signer.Close()
		return nil, errors.New("TLS certificate file is not protected")
	}
	defer clearBytes(certificateBody)
	privateKeyBody, err := readProtectedFile(
		profile.TLSPrivateKey,
		maximumTLSIdentitySize,
	)
	if err != nil {
		_ = signer.Close()
		return nil, errors.New("TLS private key file is not protected")
	}
	defer clearBytes(privateKeyBody)
	certificate, err := tls.X509KeyPair(certificateBody, privateKeyBody)
	if err != nil {
		_ = signer.Close()
		return nil, errors.New("TLS identity is invalid")
	}
	tlsLeaf, err := validateTLSIdentity(
		profile.Identifier,
		certificate,
		time.Now(),
	)
	if err != nil {
		_ = signer.Close()
		return nil, err
	}
	if err := prepareGovernancePath(profile.GovernanceFile); err != nil {
		_ = signer.Close()
		return nil, err
	}
	store, err := reference.NewFileGovernanceStore(profile.GovernanceFile)
	if err != nil {
		_ = signer.Close()
		return nil, errors.New("governance custody is invalid")
	}
	personTokenStore, err := reference.NewFilePersonTokenStore(profile.GovernanceFile + ".person-tokens")
	if err != nil {
		_ = signer.Close()
		return nil, errors.New("person-token custody is invalid")
	}
	missionIssuanceStore, err := reference.NewFileMissionIssuanceStore(profile.GovernanceFile + ".mission-issuances")
	if err != nil {
		_ = signer.Close()
		return nil, errors.New("mission-issuance custody is invalid")
	}
	authorizationStore, err := reference.OpenFileAuthorizationStateStore(reference.FileAuthorizationStateStoreConfig{
		Directory:  profile.GovernanceFile + ".authorization-state",
		MaxEntries: 4096,
		MaxBytes:   8 << 20,
	})
	if err != nil {
		_ = signer.Close()
		return nil, errors.New("authorization custody is invalid")
	}
	authorizationStoreTransferred := false
	defer func() {
		if !authorizationStoreTransferred {
			_ = authorizationStore.Close()
		}
	}()
	resolver, err := personKeyResolver(profile.TrustedKeys)
	if err != nil {
		_ = signer.Close()
		return nil, err
	}
	actions := stringSet(profile.AllowedActions)
	scopes := stringSet(profile.AllowedScopes)
	idSource, err := newPersonIDSource()
	if err != nil {
		_ = signer.Close()
		return nil, err
	}
	pendingLifetime := time.Duration(profile.PendingLifetime) * time.Second
	server, err := reference.NewPersonServer(reference.PersonServerConfig{
		Identifier:           profile.Identifier,
		SigningKey:           signingKey,
		KeyResolver:          resolver,
		Clock:                aauth.SystemClock{},
		NewID:                idSource.next,
		GovernanceStore:      store,
		PersonTokenStore:     personTokenStore,
		MissionIssuanceStore: missionIssuanceStore,
		AuthorizationStore:   authorizationStore,
		PendingLifetime:      pendingLifetime,
		PersonTokenPolicy: func(_ context.Context, request aauth.PersonTokenRequest) (aauth.PersonTokenDecision, error) {
			return aauth.PersonTokenDecision{Subject: request.Agent, Lifetime: time.Hour}, nil
		},
		CurrentMissionPolicy: func(
			_ context.Context,
			evaluation aauth.MissionEvaluation,
		) (aauth.MissionDecision, error) {
			proposal := evaluation.Proposal
			seen := make(map[string]struct{}, len(proposal.Tools))
			for _, tool := range proposal.Tools {
				if _, allowed := actions[tool.Name]; !allowed {
					return aauth.MissionDecision{}, errors.New(
						"reference deployment does not admit a proposed tool",
					)
				}
				if _, duplicate := seen[tool.Name]; duplicate {
					return aauth.MissionDecision{}, errors.New(
						"reference deployment refuses duplicate proposed tools",
					)
				}
				seen[tool.Name] = struct{}{}
			}
			return aauth.MissionDecision{
				Description: proposal.Description,
				Tools:       append([]aauth.Tool(nil), proposal.Tools...),
			}, nil
		},
		AuthorizationPolicy: func(
			_ context.Context,
			request aauth.AuthorizationRequest,
		) (aauth.AuthorizationDecision, error) {
			for _, scope := range request.Scope {
				if _, allowed := scopes[scope]; !allowed {
					return aauth.AuthorizationDecision{}, errors.New(
						"reference deployment does not admit a requested scope",
					)
				}
			}
			return aauth.AuthorizationDecision{
				Subject: request.Agent,
				Scope:   append([]string(nil), request.Scope...),
			}, nil
		},
		PermissionPolicy: func(
			_ context.Context,
			evaluation aauth.PermissionEvaluation,
		) (aauth.PermissionDecision, error) {
			if _, allowed := actions[evaluation.Request.Action]; !allowed {
				return aauth.PermissionDecision{
					Permission: aauth.PermissionDenied,
					Reason:     "action is not admitted by deployment policy",
					DecidedBy:  "reference action allowlist",
				}, nil
			}
			return aauth.PermissionDecision{
				Permission: aauth.PermissionGranted,
				DecidedBy:  "reference action allowlist",
			}, nil
		},
	})
	if err != nil {
		_ = signer.Close()
		return nil, errors.New("person server configuration is invalid")
	}
	deployment := &personDeployment{
		profile: profile,
		server:  server,
		tlsConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{certificate},
		},
		signer:             signer,
		authorizationStore: authorizationStore,
		publicKey:          signingKey.PublicJWK(),
		tlsLeaf:            tlsLeaf,
	}
	authorizationStoreTransferred = true
	return deployment, nil
}

func validateTLSIdentity(
	identifier string,
	certificate tls.Certificate,
	now time.Time,
) (*x509.Certificate, error) {
	if len(certificate.Certificate) == 0 {
		return nil, errors.New("TLS certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, errors.New("TLS leaf certificate is invalid")
	}
	parsed, err := url.Parse(identifier)
	if err != nil {
		return nil, errors.New("profile identifier is invalid")
	}
	if err := leaf.VerifyHostname(parsed.Hostname()); err != nil {
		return nil, errors.New("TLS certificate does not cover profile identifier")
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, errors.New("TLS certificate is not currently valid")
	}
	return leaf, nil
}

func (deployment *personDeployment) close() {
	if deployment == nil {
		return
	}
	if deployment.authorizationStore != nil {
		_ = deployment.authorizationStore.Close()
	}
	if deployment.signer != nil {
		_ = deployment.signer.Close()
	}
}

func validatePersonProfile(profile personProfile) error {
	if profile.Format != personProfileFormat {
		return errors.New("profile format is invalid")
	}
	if err := aauth.ValidateServerIdentifier(profile.Identifier); err != nil {
		return errors.New("profile identifier is invalid")
	}
	if strings.TrimSpace(profile.Listen) != profile.Listen || profile.Listen == "" {
		return errors.New("profile listen address is invalid")
	}
	if strings.TrimSpace(profile.KeyID) != profile.KeyID || profile.KeyID == "" {
		return errors.New("profile key id is invalid")
	}
	if len(profile.SigningKey) != ed25519.PrivateKeySize {
		return errors.New("profile signing key is invalid")
	}
	for _, path := range []string{
		profile.TLSCertificate,
		profile.TLSPrivateKey,
		profile.GovernanceFile,
	} {
		if !canonicalAbsolutePath(path) {
			return errors.New("profile custody path is invalid")
		}
	}
	if len(profile.TrustedKeys) == 0 {
		return errors.New("profile trusted keys are required")
	}
	if err := validateStringList(profile.AllowedActions, true); err != nil {
		return errors.New("profile allowed actions are invalid")
	}
	if err := validateStringList(profile.AllowedScopes, false); err != nil {
		return errors.New("profile allowed scopes are invalid")
	}
	if profile.PendingLifetime < 0 || profile.PendingLifetime > int64((24*time.Hour)/time.Second) {
		return errors.New("profile pending lifetime is invalid")
	}
	return nil
}

func personKeyResolver(
	trusted map[string][]jose.JWK,
) (signaturekey.StaticKeyResolver, error) {
	resolver := make(signaturekey.StaticKeyResolver, len(trusted))
	for issuer, keys := range trusted {
		if err := aauth.ValidateServerIdentifier(issuer); err != nil || len(keys) == 0 {
			return nil, errors.New("profile trusted issuer is invalid")
		}
		issuerKeys := make(map[string]jose.JWK, len(keys))
		for _, key := range keys {
			if strings.TrimSpace(key.Kid) != key.Kid || key.Kid == "" {
				return nil, errors.New("profile trusted key id is invalid")
			}
			if _, err := key.PublicKey(); err != nil {
				return nil, errors.New("profile trusted key is invalid")
			}
			if _, duplicate := issuerKeys[key.Kid]; duplicate {
				return nil, errors.New("profile trusted key is duplicated")
			}
			issuerKeys[key.Kid] = key
		}
		resolver[issuer] = issuerKeys
	}
	return resolver, nil
}

func validateStringList(values []string, required bool) error {
	if required && len(values) == 0 {
		return errors.New("list is required")
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != value || value == "" {
			return errors.New("list entry is invalid")
		}
		if _, duplicate := seen[value]; duplicate {
			return errors.New("list entry is duplicated")
		}
		seen[value] = struct{}{}
	}
	return nil
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

type personIDSource struct {
	seed    [32]byte
	counter atomic.Uint64
}

func newPersonIDSource() (*personIDSource, error) {
	source := &personIDSource{}
	if _, err := io.ReadFull(cryptorand.Reader, source.seed[:]); err != nil {
		return nil, errors.New("secure person id source is unavailable")
	}
	return source, nil
}

func (source *personIDSource) next() string {
	counter := source.counter.Add(1)
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)
	digest := sha256.New()
	_, _ = digest.Write(source.seed[:])
	_, _ = digest.Write(counterBytes[:])
	return "reference-" + hex.EncodeToString(digest.Sum(nil)[:16])
}

type protectedSigner struct {
	mu      sync.RWMutex
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

func newProtectedSigner(privateKey ed25519.PrivateKey) (*protectedSigner, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("profile protected signer is invalid")
	}
	privateCopy := append(ed25519.PrivateKey(nil), privateKey...)
	publicCopy := append(
		ed25519.PublicKey(nil),
		privateCopy.Public().(ed25519.PublicKey)...,
	)
	return &protectedSigner{private: privateCopy, public: publicCopy}, nil
}

func (signer *protectedSigner) Public() crypto.PublicKey {
	if signer == nil {
		return ed25519.PublicKey(nil)
	}
	signer.mu.RLock()
	defer signer.mu.RUnlock()
	return append(ed25519.PublicKey(nil), signer.public...)
}

func (signer *protectedSigner) Sign(
	_ io.Reader,
	message []byte,
	options crypto.SignerOpts,
) ([]byte, error) {
	if signer == nil || options == nil || options.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("protected signer request is invalid")
	}
	signer.mu.RLock()
	defer signer.mu.RUnlock()
	if len(signer.private) != ed25519.PrivateKeySize {
		return nil, errors.New("protected signer is closed")
	}
	return ed25519.Sign(signer.private, message), nil
}

func (signer *protectedSigner) Close() error {
	if signer == nil {
		return nil
	}
	signer.mu.Lock()
	defer signer.mu.Unlock()
	clearBytes(signer.private)
	clearBytes(signer.public)
	signer.private = nil
	signer.public = nil
	return nil
}

func readProtectedFile(path string, maximum int64) ([]byte, error) {
	if !canonicalAbsolutePath(path) {
		return nil, errors.New("protected file path is invalid")
	}
	resolvedParent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil || filepath.Clean(resolvedParent) != filepath.Dir(path) {
		return nil, errors.New("protected file parent is unsafe")
	}
	before, err := os.Lstat(path)
	if err != nil || !validProtectedFile(before) {
		return nil, errors.New("protected file metadata is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("protected file could not be opened")
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !validProtectedFile(after) {
		return nil, errors.New("protected file changed while opening")
	}
	body, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(body) == 0 || int64(len(body)) > maximum {
		return nil, errors.New("protected file size is invalid")
	}
	return body, nil
}

func validProtectedFile(info os.FileInfo) bool {
	status, ok := info.Sys().(*syscall.Stat_t)
	return ok &&
		info.Mode().IsRegular() &&
		info.Mode().Perm() == 0o600 &&
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 &&
		status.Uid == uint32(os.Geteuid()) &&
		status.Nlink == 1
}

func prepareGovernancePath(path string) error {
	if !canonicalAbsolutePath(path) {
		return errors.New("governance path is invalid")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return errors.New("governance directory could not be created")
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || filepath.Clean(resolved) != directory {
		return errors.New("governance directory is unsafe")
	}
	info, err := os.Lstat(directory)
	if err != nil ||
		!info.IsDir() ||
		info.Mode().Perm() != 0o700 ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errors.New("governance directory is not protected")
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok || status.Uid != uint32(os.Geteuid()) {
		return errors.New("governance directory owner is invalid")
	}
	fileInfo, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !validProtectedFile(fileInfo) {
		return errors.New("existing governance file is not protected")
	}
	return nil
}

func canonicalAbsolutePath(path string) bool {
	if strings.TrimSpace(path) != path || path == "" {
		return false
	}
	absolute, err := filepath.Abs(path)
	return err == nil && filepath.Clean(absolute) == path
}

func unmarshalSingleJSON(body []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON content")
	}
	return nil
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

var _ crypto.Signer = (*protectedSigner)(nil)
