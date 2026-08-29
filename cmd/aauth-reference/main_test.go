package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
)

func TestPersonProcessServesDurableGovernanceOverTLS(t *testing.T) {
	tempDir := t.TempDir()
	binary := filepath.Join(tempDir, "aauth-reference")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build aauth-reference: %v\n%s", err, output)
	}

	apKey, _ := processTestSigningKey(t, "process-ap")
	personKey, personPrivate := processTestSigningKey(t, "process-person")
	agentKey, _ := processTestSigningKey(t, "process-agent")
	certificatePath, tlsKeyPath, roots := writeProcessTestTLSIdentity(
		t,
		tempDir,
		"person.example",
	)
	governancePath := filepath.Join(tempDir, "state", "person-governance.json")
	profilePath := filepath.Join(tempDir, "person-profile.json")
	profile := map[string]any{
		"format":          "aauth.reference.person-profile.v0",
		"identifier":      "https://person.example",
		"listen":          "127.0.0.1:0",
		"key_id":          personKey.ID(),
		"signing_key":     []byte(personPrivate),
		"tls_certificate": certificatePath,
		"tls_private_key": tlsKeyPath,
		"governance_file": governancePath,
		"trusted_keys": map[string][]jose.JWK{
			"https://ap.example": {apKey.PublicJWK()},
		},
		"allowed_actions": []string{"store.backup.create"},
	}
	writeProcessTestJSON(t, profilePath, profile, 0o600)

	agentToken, err := aauth.MintAgentToken(
		"https://ap.example",
		apKey,
		aauth.AgentTokenRequest{
			Agent:        "aauth:operator@ap.example",
			PersonServer: "https://person.example",
			PublicKey:    agentKey.PublicJWK(),
			Lifetime:     2 * time.Hour,
		},
		time.Now(),
		"process-agent-token",
	)
	if err != nil {
		t.Fatal(err)
	}
	resolver := signaturekey.StaticKeyResolver{
		"https://ap.example": {apKey.ID(): apKey.PublicJWK()},
	}

	first := startPersonProcess(t, binary, profilePath)
	agent := processTestAgent(t, first.ready.Listen, roots, agentKey, agentToken, resolver)
	mission, err := agent.CreateMission(
		context.Background(),
		"https://person.example/mission",
		aauth.MissionProposal{
			Description: "Create recoverable backups.",
			Tools: []aauth.Tool{{
				Name:        "store.backup.create",
				Description: "Create one durable backup.",
			}},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := agent.RequestPermission(
		context.Background(),
		"https://person.example/permission",
		aauth.PermissionRequest{
			Action:      "store.backup.create",
			Description: "Create the first backup.",
			Parameters:  map[string]any{"request": "first"},
			Mission:     &mission.Reference,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if authorization.Decision == nil ||
		authorization.Decision.Permission != aauth.PermissionGranted {
		t.Fatalf("first process permission = %#v", authorization)
	}
	if err := agent.RecordAudit(
		context.Background(),
		"https://person.example/audit",
		aauth.AuditRequest{
			Mission:     mission.Reference,
			Action:      "store.backup.create",
			Description: "The first backup completed.",
			Parameters:  map[string]any{"request": "first"},
			Result:      map[string]any{"status": "succeeded"},
		},
	); err != nil {
		t.Fatal(err)
	}
	denied, err := agent.RequestPermission(
		context.Background(),
		"https://person.example/permission",
		aauth.PermissionRequest{
			Action:      "system.shutdown",
			Description: "Attempt an action outside deployment policy.",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if denied.Decision == nil ||
		denied.Decision.Permission != aauth.PermissionDenied ||
		denied.Decision.Reason == "" {
		t.Fatalf("unlisted action permission = %#v", denied)
	}
	first.stop(t)
	firstState := processTestFile(t, governancePath)

	second := startPersonProcess(t, binary, profilePath)
	agent = processTestAgent(t, second.ready.Listen, roots, agentKey, agentToken, resolver)
	authorization, err = agent.RequestPermission(
		context.Background(),
		"https://person.example/permission",
		aauth.PermissionRequest{
			Action:      "store.backup.create",
			Description: "Create the second backup after restart.",
			Parameters:  map[string]any{"request": "second"},
			Mission:     &mission.Reference,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if authorization.Decision == nil ||
		authorization.Decision.Permission != aauth.PermissionGranted {
		t.Fatalf("restart permission = %#v", authorization)
	}
	if err := agent.RecordAudit(
		context.Background(),
		"https://person.example/audit",
		aauth.AuditRequest{
			Mission:     mission.Reference,
			Action:      "store.backup.create",
			Description: "The second backup completed.",
			Parameters:  map[string]any{"request": "second"},
			Result:      map[string]any{"status": "succeeded"},
		},
	); err != nil {
		t.Fatal(err)
	}
	second.stop(t)
	secondState := processTestFile(t, governancePath)
	if bytes.Equal(firstState, secondState) {
		t.Fatal("restart journey did not advance durable person-server governance")
	}
	info, err := os.Lstat(governancePath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("governance custody mode = %v", info.Mode())
	}
}

func TestPersonProcessRejectsUnprotectedProfile(t *testing.T) {
	tempDir := t.TempDir()
	profilePath := filepath.Join(tempDir, "person-profile.json")
	writeProcessTestJSON(t, profilePath, map[string]any{
		"format":      "aauth.reference.person-profile.v0",
		"signing_key": []byte("must-not-leak"),
	}, 0o644)
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"serve", "person", "--profile", profilePath},
		&stdout,
		&stderr,
	)
	if code == 0 || stdout.Len() != 0 {
		t.Fatalf("unprotected profile exit/stdout = %d/%q", code, stdout.String())
	}
	if strings.Contains(stderr.String(), "must-not-leak") {
		t.Fatalf("profile secret reached stderr: %q", stderr.String())
	}
}

func TestPersonDeploymentReleasesAuthorizationStoreLockOnCompositionFailure(t *testing.T) {
	tempDir := t.TempDir()
	trustedKey, _ := processTestSigningKey(t, "trusted-key")
	personKey, personPrivate := processTestSigningKey(t, "person-key")
	certificatePath, tlsKeyPath, _ := writeProcessTestTLSIdentity(t, tempDir, "person.example")
	governancePath := filepath.Join(tempDir, "state", "person-governance.json")
	profilePath := filepath.Join(tempDir, "person-profile.json")
	writeProcessTestJSON(t, profilePath, map[string]any{
		"format":          "aauth.reference.person-profile.v0",
		"identifier":      "https://person.example",
		"listen":          "127.0.0.1:0",
		"key_id":          personKey.ID(),
		"signing_key":     []byte(personPrivate),
		"tls_certificate": certificatePath,
		"tls_private_key": tlsKeyPath,
		"governance_file": governancePath,
		"trusted_keys": map[string][]jose.JWK{
			"not-a-server-identifier": {trustedKey.PublicJWK()},
		},
		"allowed_actions": []string{"store.backup.create"},
	}, 0o600)

	if _, err := loadPersonDeployment(profilePath); err == nil {
		t.Fatal("invalid trusted issuer unexpectedly composed a person deployment")
	}
	authorizationStore, err := reference.OpenFileAuthorizationStateStore(reference.FileAuthorizationStateStoreConfig{
		Directory:  governancePath + ".authorization-state",
		MaxEntries: 4096,
		MaxBytes:   8 << 20,
	})
	if err != nil {
		t.Fatalf("composition failure retained authorization-store lock: %v", err)
	}
	if err := authorizationStore.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestProtectedFileCustodyRefusesAliases(t *testing.T) {
	tempDir := t.TempDir()
	source := filepath.Join(tempDir, "source")
	writeProcessTestFile(t, source, []byte("protected"), 0o600)
	if body, err := readProtectedFile(source, 1024); err != nil ||
		string(body) != "protected" {
		t.Fatalf("protected file = %q, %v", body, err)
	}

	hardlink := filepath.Join(tempDir, "hardlink")
	if err := os.Link(source, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedFile(source, 1024); err == nil {
		t.Fatal("multiply-linked protected file was accepted")
	}

	symlink := filepath.Join(tempDir, "symlink")
	if err := os.Symlink(source, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedFile(symlink, 1024); err == nil {
		t.Fatal("symlinked protected file was accepted")
	}

	realDirectory := filepath.Join(tempDir, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	viaSymlink := filepath.Join(tempDir, "via-symlink")
	if err := os.Symlink(realDirectory, viaSymlink); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(realDirectory, "nested")
	writeProcessTestFile(t, nested, []byte("protected"), 0o600)
	if _, err := readProtectedFile(
		filepath.Join(viaSymlink, "nested"),
		1024,
	); err == nil {
		t.Fatal("protected file below a symlinked directory was accepted")
	}
}

type personProcessReady struct {
	Schema     string `json:"schema"`
	Identifier string `json:"identifier"`
	Listen     string `json:"listen"`
}

type runningPersonProcess struct {
	command *exec.Cmd
	ready   personProcessReady
	stderr  *bytes.Buffer
	stopped bool
}

func startPersonProcess(
	t *testing.T,
	binary string,
	profilePath string,
) *runningPersonProcess {
	t.Helper()
	command := exec.Command(binary, "serve", "person", "--profile", profilePath)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := &bytes.Buffer{}
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	process := &runningPersonProcess{command: command, stderr: stderr}
	t.Cleanup(func() {
		if !process.stopped {
			_ = process.command.Process.Kill()
			_ = process.command.Wait()
		}
	})
	line := make(chan []byte, 1)
	scanErr := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			line <- append([]byte(nil), scanner.Bytes()...)
			return
		}
		scanErr <- scanner.Err()
	}()
	select {
	case body := <-line:
		if err := json.Unmarshal(body, &process.ready); err != nil {
			t.Fatalf("decode readiness %q: %v", body, err)
		}
	case err := <-scanErr:
		t.Fatalf("person process readiness ended: %v\nstderr:\n%s", err, stderr)
	case <-time.After(10 * time.Second):
		t.Fatalf("person process readiness timed out\nstderr:\n%s", stderr)
	}
	if process.ready.Schema != "aauth.reference.person-ready.v0" ||
		process.ready.Identifier != "https://person.example" ||
		process.ready.Listen == "" {
		t.Fatalf("person process readiness = %#v", process.ready)
	}
	return process
}

func (process *runningPersonProcess) stop(t *testing.T) {
	t.Helper()
	if process.stopped {
		return
	}
	if err := process.command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := process.command.Wait(); err != nil {
		t.Fatalf("person process shutdown: %v\nstderr:\n%s", err, process.stderr)
	}
	process.stopped = true
}

func processTestAgent(
	t *testing.T,
	target string,
	roots *x509.CertPool,
	key jose.SigningKey,
	token string,
	resolver signaturekey.KeyResolver,
) *reference.Agent {
	t.Helper()
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    roots,
		},
		DialContext: func(
			ctx context.Context,
			network string,
			_ string,
		) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, target)
		},
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	authorizationStore, err := reference.NewMemoryAuthorizationStateStore(128, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	agent, err := reference.NewAgent(reference.AgentConfig{
		AuthorizationStore: authorizationStore,
		Identifier:         "aauth:operator@ap.example",
		SigningKey:         key, AgentToken: token, KeyResolver: resolver,
		HTTPClient: client, Clock: aauth.SystemClock{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return agent
}

func processTestSigningKey(
	t *testing.T,
	id string,
) (jose.SigningKey, ed25519.PrivateKey) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jose.NewEd25519SigningKey(id, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return key, privateKey
}

func writeProcessTestTLSIdentity(
	t *testing.T,
	root string,
	host string,
) (string, string, *x509.CertPool) {
	t.Helper()
	now := time.Now()
	caPublic, caPrivate, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "AAuth reference test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(
		cryptorand.Reader,
		caTemplate,
		caTemplate,
		caPublic,
		caPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, leafPrivate, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(
		cryptorand.Reader,
		leafTemplate,
		caTemplate,
		leafPublic,
		caPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	certificatePath := filepath.Join(root, "person-cert.pem")
	tlsKeyPath := filepath.Join(root, "person-tls-key.pem")
	certificate := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...,
	)
	privateDER, err := x509.MarshalPKCS8PrivateKey(leafPrivate)
	if err != nil {
		t.Fatal(err)
	}
	writeProcessTestFile(t, certificatePath, certificate, 0o600)
	writeProcessTestFile(
		t,
		tlsKeyPath,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
		0o600,
	)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
	) {
		t.Fatal("could not add generated CA")
	}
	return certificatePath, tlsKeyPath, roots
}

func writeProcessTestJSON(
	t *testing.T,
	path string,
	value any,
	mode os.FileMode,
) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	writeProcessTestFile(t, path, body, mode)
}

func writeProcessTestFile(
	t *testing.T,
	path string,
	body []byte,
	mode os.FileMode,
) {
	t.Helper()
	if err := os.WriteFile(path, body, mode); err != nil {
		t.Fatal(err)
	}
}

func processTestFile(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestUsagePreservesVerbObjectGrammar(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"person", "serve"}, &stdout, &stderr)
	if code != 2 || stdout.Len() != 0 ||
		!strings.Contains(stderr.String(), "aauth-reference serve person") ||
		!strings.Contains(stderr.String(), "aauth-reference diagnose person") ||
		!strings.Contains(stderr.String(), "aauth-reference demo person") ||
		!strings.Contains(stderr.String(), "aauth-reference verify coverage") {
		t.Fatalf(
			"retired grammar exit/stdout/stderr = %d/%q/%q",
			code,
			stdout.String(),
			stderr.String(),
		)
	}
}

func TestCoverageVerificationDefaultsToRetainedRepositorySources(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{
			"verify",
			"coverage",
			"--repo",
			filepath.Join("..", ".."),
		},
		&stdout,
		&stderr,
	)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf(
			"default-source verification exit/stderr = %d/%q",
			code,
			stderr.String(),
		)
	}
	if !strings.Contains(stdout.String(), `"status":"verified"`) {
		t.Fatalf("default-source verification stdout = %q", stdout.String())
	}
}

func TestCoverageVerificationRejectsMissingPinnedSources(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{
			"verify",
			"coverage",
			"--source-dir",
			t.TempDir(),
			"--repo",
			filepath.Join("..", ".."),
		},
		&stdout,
		&stderr,
	)
	if code != 1 || stdout.Len() != 0 {
		t.Fatalf("coverage verification exit/stdout = %d/%q", code, stdout.String())
	}
	if !strings.Contains(stderr.String(), "pinned sources do not verify") {
		t.Fatalf("coverage verification error = %q", stderr.String())
	}
}

func Example_usage() {
	fmt.Println("aauth-reference serve person --profile FILE")
	// Output: aauth-reference serve person --profile FILE
}
