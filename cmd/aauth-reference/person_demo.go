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
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
)

const personDemoFormat = "aauth.reference.person-demo.v0"

type personDemoResult struct {
	Schema               string `json:"schema"`
	Status               string `json:"status"`
	MissionCreated       bool   `json:"mission_created"`
	PermissionGranted    bool   `json:"permission_granted"`
	AuditRecorded        bool   `json:"audit_recorded"`
	UnlistedActionDenied bool   `json:"unlisted_action_denied"`
	RestartRecovered     bool   `json:"restart_recovered"`
	GovernancePersisted  bool   `json:"governance_persisted"`
}

type personDemoMaterial struct {
	profilePath    string
	governancePath string
	roots          *x509.CertPool
	agentKey       aauth.SigningKey
	agentToken     string
	resolver       aauth.StaticKeyResolver
	clear          func()
}

func runPersonDemo(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) != 0 {
		writeUsage(stderr)
		return 2
	}
	executable, err := os.Executable()
	if err != nil {
		fmt.Fprintln(stderr, "aauth-reference: person demo failed: executable identity")
		return 1
	}
	result, err := executePersonDemo(executable)
	if err != nil {
		fmt.Fprintf(stderr, "aauth-reference: person demo failed: %v\n", err)
		return 1
	}
	body, err := json.Marshal(result)
	if err != nil {
		fmt.Fprintln(stderr, "aauth-reference: person demo failed: encode result")
		return 1
	}
	if _, err := fmt.Fprintln(stdout, string(body)); err != nil {
		fmt.Fprintln(stderr, "aauth-reference: person demo failed: publish result")
		return 1
	}
	return 0
}

func executePersonDemo(executable string) (personDemoResult, error) {
	var result personDemoResult
	root, err := os.MkdirTemp("", "aauth-reference-person-demo-")
	if err != nil {
		return result, errors.New("create protected workspace")
	}
	defer os.RemoveAll(root)
	if err := os.Chmod(root, 0o700); err != nil {
		return result, errors.New("protect workspace")
	}
	material, err := createPersonDemoMaterial(root)
	if err != nil {
		return result, err
	}
	defer material.clear()

	first, err := startDemoPersonProcess(executable, material.profilePath)
	if err != nil {
		return result, err
	}
	defer first.terminate()
	agent, closeAgent, err := newDemoAgent(first.ready.Listen, material)
	if err != nil {
		return result, err
	}
	mission, err := agent.CreateMission(
		context.Background(),
		"https://person.example/mission",
		aauth.MissionProposal{
			Description: "Demonstrate durable AAuth authority.",
			Tools: []aauth.Tool{{
				Name:        "store.backup.create",
				Description: "Create one durable backup.",
			}},
		},
	)
	if err != nil {
		closeAgent()
		return result, errors.New("create mission")
	}
	authorization, err := agent.RequestPermission(
		context.Background(),
		"https://person.example/permission",
		aauth.PermissionRequest{
			Action:      "store.backup.create",
			Description: "Create the first demonstration backup.",
			Parameters:  map[string]any{"request": "first"},
			Mission:     &mission.Reference,
		},
	)
	if err != nil ||
		authorization.Decision == nil ||
		authorization.Decision.Permission != aauth.PermissionGranted {
		closeAgent()
		return result, errors.New("obtain mission-bound permission")
	}
	if err := agent.RecordAudit(
		context.Background(),
		"https://person.example/audit",
		aauth.AuditRequest{
			Mission:     mission.Reference,
			Action:      "store.backup.create",
			Description: "The first demonstration backup completed.",
			Parameters:  map[string]any{"request": "first"},
			Result:      map[string]any{"status": "succeeded"},
		},
	); err != nil {
		closeAgent()
		return result, errors.New("record outcome audit")
	}
	denied, err := agent.RequestPermission(
		context.Background(),
		"https://person.example/permission",
		aauth.PermissionRequest{
			Action:      "system.shutdown",
			Description: "Prove default-deny deployment policy.",
		},
	)
	closeAgent()
	if err != nil ||
		denied.Decision == nil ||
		denied.Decision.Permission != aauth.PermissionDenied {
		return result, errors.New("verify unlisted-action denial")
	}
	if err := first.stop(); err != nil {
		return result, err
	}
	firstState, err := os.ReadFile(material.governancePath)
	if err != nil || len(firstState) == 0 {
		return result, errors.New("read first durable governance state")
	}

	second, err := startDemoPersonProcess(executable, material.profilePath)
	if err != nil {
		return result, err
	}
	defer second.terminate()
	agent, closeAgent, err = newDemoAgent(second.ready.Listen, material)
	if err != nil {
		return result, err
	}
	authorization, err = agent.RequestPermission(
		context.Background(),
		"https://person.example/permission",
		aauth.PermissionRequest{
			Action:      "store.backup.create",
			Description: "Create a backup after person-server restart.",
			Parameters:  map[string]any{"request": "second"},
			Mission:     &mission.Reference,
		},
	)
	if err != nil ||
		authorization.Decision == nil ||
		authorization.Decision.Permission != aauth.PermissionGranted {
		closeAgent()
		return result, errors.New("recover mission after restart")
	}
	if err := agent.RecordAudit(
		context.Background(),
		"https://person.example/audit",
		aauth.AuditRequest{
			Mission:     mission.Reference,
			Action:      "store.backup.create",
			Description: "The post-restart demonstration backup completed.",
			Parameters:  map[string]any{"request": "second"},
			Result:      map[string]any{"status": "succeeded"},
		},
	); err != nil {
		closeAgent()
		return result, errors.New("record post-restart audit")
	}
	closeAgent()
	if err := second.stop(); err != nil {
		return result, err
	}
	secondState, err := os.ReadFile(material.governancePath)
	if err != nil || len(secondState) == 0 || bytes.Equal(firstState, secondState) {
		return result, errors.New("verify durable governance advancement")
	}
	info, err := os.Lstat(material.governancePath)
	if err != nil || !validProtectedFile(info) {
		return result, errors.New("verify durable governance custody")
	}
	return personDemoResult{
		Schema:               personDemoFormat,
		Status:               "verified",
		MissionCreated:       true,
		PermissionGranted:    true,
		AuditRecorded:        true,
		UnlistedActionDenied: true,
		RestartRecovered:     true,
		GovernancePersisted:  true,
	}, nil
}

func createPersonDemoMaterial(root string) (personDemoMaterial, error) {
	var material personDemoMaterial
	apKey, apPrivate, err := newDemoSigningKey("demo-ap")
	if err != nil {
		return material, errors.New("create agent-provider identity")
	}
	personKey, personPrivate, err := newDemoSigningKey("demo-person")
	if err != nil {
		clearBytes(apPrivate)
		return material, errors.New("create person identity")
	}
	agentKey, agentPrivate, err := newDemoSigningKey("demo-agent")
	if err != nil {
		clearBytes(apPrivate)
		clearBytes(personPrivate)
		return material, errors.New("create agent identity")
	}
	material.clear = func() {
		clearBytes(apPrivate)
		clearBytes(personPrivate)
		clearBytes(agentPrivate)
	}
	certificatePath, privateKeyPath, roots, err := createDemoTLSIdentity(
		root,
		"person.example",
	)
	if err != nil {
		material.clear()
		return personDemoMaterial{}, err
	}
	material.profilePath = filepath.Join(root, "person-profile.json")
	material.governancePath = filepath.Join(root, "state", "person-governance.json")
	profileBody, err := json.Marshal(personProfile{
		Format:         personProfileFormat,
		Identifier:     "https://person.example",
		Listen:         "127.0.0.1:0",
		KeyID:          personKey.ID(),
		SigningKey:     personPrivate,
		TLSCertificate: certificatePath,
		TLSPrivateKey:  privateKeyPath,
		GovernanceFile: material.governancePath,
		TrustedKeys: map[string][]aauth.JWK{
			"https://ap.example": {apKey.PublicJWK()},
		},
		AllowedActions: []string{"store.backup.create"},
	})
	if err != nil {
		material.clear()
		return personDemoMaterial{}, errors.New("encode person profile")
	}
	defer clearBytes(profileBody)
	if err := writeExclusiveProtectedFile(material.profilePath, profileBody); err != nil {
		material.clear()
		return personDemoMaterial{}, errors.New("write protected person profile")
	}
	token, err := aauth.MintAgentToken(
		"https://ap.example",
		apKey,
		aauth.AgentTokenRequest{
			Agent:        "aauth:demo@ap.example",
			PersonServer: "https://person.example",
			PublicKey:    agentKey.PublicJWK(),
			Lifetime:     time.Hour,
		},
		time.Now(),
		"demo-agent-token",
	)
	if err != nil {
		material.clear()
		return personDemoMaterial{}, errors.New("mint demonstration agent token")
	}
	material.roots = roots
	material.agentKey = agentKey
	material.agentToken = token
	material.resolver = aauth.StaticKeyResolver{
		"https://ap.example": {apKey.ID(): apKey.PublicJWK()},
	}
	return material, nil
}

func newDemoSigningKey(id string) (aauth.SigningKey, ed25519.PrivateKey, error) {
	_, privateKey, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		return aauth.SigningKey{}, nil, err
	}
	key, err := aauth.NewEd25519SigningKey(id, privateKey)
	if err != nil {
		clearBytes(privateKey)
		return aauth.SigningKey{}, nil, err
	}
	return key, privateKey, nil
}

func createDemoTLSIdentity(
	root string,
	host string,
) (string, string, *x509.CertPool, error) {
	now := time.Now()
	caPublic, caPrivate, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		return "", "", nil, errors.New("create demonstration CA")
	}
	defer clearBytes(caPrivate)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "AAuth reference demonstration CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
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
		return "", "", nil, errors.New("create demonstration CA certificate")
	}
	leafPublic, leafPrivate, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		return "", "", nil, errors.New("create demonstration TLS identity")
	}
	defer clearBytes(leafPrivate)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
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
		return "", "", nil, errors.New("create demonstration TLS certificate")
	}
	certificateBody := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...,
	)
	defer clearBytes(certificateBody)
	privateDER, err := x509.MarshalPKCS8PrivateKey(leafPrivate)
	if err != nil {
		return "", "", nil, errors.New("encode demonstration TLS key")
	}
	defer clearBytes(privateDER)
	privateBody := pem.EncodeToMemory(
		&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER},
	)
	defer clearBytes(privateBody)
	certificatePath := filepath.Join(root, "person-chain.pem")
	privateKeyPath := filepath.Join(root, "person-tls-key.pem")
	if err := writeExclusiveProtectedFile(certificatePath, certificateBody); err != nil {
		return "", "", nil, errors.New("write demonstration TLS certificate")
	}
	if err := writeExclusiveProtectedFile(privateKeyPath, privateBody); err != nil {
		return "", "", nil, errors.New("write demonstration TLS key")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
	) {
		return "", "", nil, errors.New("load demonstration CA")
	}
	return certificatePath, privateKeyPath, roots, nil
}

func writeExclusiveProtectedFile(path string, body []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		_ = file.Close()
		if !complete {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(body); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	complete = true
	return nil
}

type demoPersonProcess struct {
	command *exec.Cmd
	ready   personReady
	stderr  *bytes.Buffer
	running bool
}

func startDemoPersonProcess(executable string, profilePath string) (*demoPersonProcess, error) {
	command := exec.Command(executable, "serve", "person", "--profile", profilePath)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, errors.New("prepare person process output")
	}
	stderr := &bytes.Buffer{}
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		return nil, errors.New("start person process")
	}
	process := &demoPersonProcess{
		command: command,
		stderr:  stderr,
		running: true,
	}
	line := make(chan []byte, 1)
	readErr := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			line <- append([]byte(nil), scanner.Bytes()...)
			return
		}
		readErr <- scanner.Err()
	}()
	select {
	case body := <-line:
		if err := json.Unmarshal(body, &process.ready); err != nil {
			process.terminate()
			return nil, errors.New("decode person process readiness")
		}
	case <-readErr:
		process.terminate()
		return nil, errors.New("person process ended before readiness")
	case <-time.After(10 * time.Second):
		process.terminate()
		return nil, errors.New("person process readiness timed out")
	}
	if process.ready.Schema != personReadyFormat ||
		process.ready.Identifier != "https://person.example" ||
		process.ready.Listen == "" {
		process.terminate()
		return nil, errors.New("person process readiness is invalid")
	}
	return process, nil
}

func (process *demoPersonProcess) stop() error {
	if process == nil || !process.running {
		return nil
	}
	if err := process.command.Process.Signal(syscall.SIGTERM); err != nil {
		process.terminate()
		return errors.New("signal person process")
	}
	result := make(chan error, 1)
	go func() {
		result <- process.command.Wait()
	}()
	select {
	case err := <-result:
		process.running = false
		if err != nil {
			return errors.New("stop person process")
		}
		return nil
	case <-time.After(10 * time.Second):
		process.terminate()
		return errors.New("person process shutdown timed out")
	}
}

func (process *demoPersonProcess) terminate() {
	if process == nil || !process.running {
		return
	}
	_ = process.command.Process.Kill()
	_ = process.command.Wait()
	process.running = false
}

func newDemoAgent(
	target string,
	material personDemoMaterial,
) (*reference.Agent, func(), error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    material.roots,
		},
		DialContext: func(
			ctx context.Context,
			network string,
			_ string,
		) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, target)
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}
	agent, err := reference.NewAgent(reference.AgentConfig{
		Identifier:  "aauth:demo@ap.example",
		SigningKey:  material.agentKey,
		AgentToken:  material.agentToken,
		KeyResolver: material.resolver,
		HTTPClient:  client,
		Clock:       aauth.SystemClock{},
	})
	if err != nil {
		transport.CloseIdleConnections()
		return nil, func() {}, errors.New("compose demonstration agent")
	}
	return agent, transport.CloseIdleConnections, nil
}
