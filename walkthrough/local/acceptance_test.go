package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type actionResult struct {
	Status           string `json:"status"`
	Agent            string `json:"agent"`
	RequestKey       string `json:"request_key"`
	Result           string `json:"result"`
	Replayed         bool   `json:"replayed"`
	ConsequenceCount int    `json:"consequence_count"`
}

func TestLocalWalkthroughSurvivesRestartAndRevocation(t *testing.T) {
	stateDir := t.TempDir()
	command := buildWalkthrough(t)
	agentAddress := freeAddress(t)
	serviceAddress := freeAddress(t)

	run(t, command,
		"init",
		"--state", stateDir,
		"--agent-address", agentAddress,
		"--service-address", serviceAddress,
	)
	assertDistinctRoleKeys(t, stateDir)

	service := start(t, command, "service", "--state", stateDir)
	agent := start(t, command, "agent", "--state", stateDir)
	waitForHealth(t, stateDir, "agent.local", agentAddress)
	waitForHealth(t, stateDir, "person.local", serviceAddress)
	waitForHealth(t, stateDir, "resource.local", serviceAddress)
	assertUnauthenticatedControlRefused(t, command, stateDir, agentAddress)
	assertUnsignedRequestRefusedBeforeConsequence(t, command, stateDir, serviceAddress)

	first := runAction(t, command, stateDir, "local-write-1")
	if first.Status != "completed" || first.Agent != "aauth:local@agent.local" || first.RequestKey != "local-write-1" ||
		first.Result != "note-1" || first.Replayed || first.ConsequenceCount != 1 {
		t.Fatalf("first action = %#v", first)
	}

	stop(t, agent)
	stop(t, service)
	// Model a crash after the Resource committed the note but before the Agent
	// durably retained its response. The same request key must recover from the
	// Resource without creating a second note.
	if err := os.Remove(filepath.Join(stateDir, "agent-results.json")); err != nil {
		t.Fatal(err)
	}

	service = start(t, command, "service", "--state", stateDir)
	agent = start(t, command, "agent", "--state", stateDir)
	t.Cleanup(func() {
		stop(t, agent)
		stop(t, service)
	})
	waitForHealth(t, stateDir, "agent.local", agentAddress)
	waitForHealth(t, stateDir, "person.local", serviceAddress)
	waitForHealth(t, stateDir, "resource.local", serviceAddress)

	replayed := runAction(t, command, stateDir, "local-write-1")
	if replayed.Status != "completed" || replayed.Result != "note-1" ||
		!replayed.Replayed || replayed.ConsequenceCount != 1 {
		t.Fatalf("replayed action = %#v", replayed)
	}

	run(t, command, "revoke", "--state", stateDir)
	output, err := runFail(command, "act", "--state", stateDir, "--request-key", "local-write-2")
	if err == nil {
		t.Fatalf("post-revocation action succeeded: %s", output)
	}
	if !strings.Contains(output, "revoked_jwt") {
		t.Fatalf("post-revocation refusal = %q, want revoked_jwt", output)
	}

	status := runActionCommand(t, command, "status", "--state", stateDir)
	if status.ConsequenceCount != 1 {
		t.Fatalf("status after refusal = %#v, want one consequence", status)
	}
}

func assertUnauthenticatedControlRefused(t *testing.T, command, stateDir, agentAddress string) {
	t.Helper()
	client := walkthroughHTTPClient(t, stateDir, "agent.local", agentAddress)
	request, err := http.NewRequest(http.MethodPost, "https://agent.local/control/act", strings.NewReader(`{"request_key":"unauthenticated-write"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated control request = %s", response.Status)
	}
	status := runActionCommand(t, command, "status", "--state", stateDir)
	if status.ConsequenceCount != 0 {
		t.Fatalf("unauthenticated control request executed a consequence: %#v", status)
	}
}

func assertDistinctRoleKeys(t *testing.T, stateDir string) {
	t.Helper()
	keys := make(map[string]string)
	for _, role := range []string{"agent", "person", "resource"} {
		encoded, err := os.ReadFile(filepath.Join(stateDir, role+"-aauth.key"))
		if err != nil {
			t.Fatal(err)
		}
		value := string(encoded)
		if previous, duplicate := keys[value]; duplicate {
			t.Fatalf("%s and %s share one AAuth private key", previous, role)
		}
		keys[value] = role
	}
}

func assertUnsignedRequestRefusedBeforeConsequence(t *testing.T, command, stateDir, serviceAddress string) {
	t.Helper()
	client := walkthroughHTTPClient(t, stateDir, "resource.local", serviceAddress)
	request, err := http.NewRequest(http.MethodPost, "https://resource.local/notes", strings.NewReader(`{"text":"unsigned"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "unsigned-write")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned request = %s, headers %v", response.Status, response.Header)
	}
	if response.Header.Get("AAuth-Requirement") != "requirement=agent-token" {
		t.Fatalf("unsigned request requirement = %q, headers %v", response.Header.Get("AAuth-Requirement"), response.Header)
	}
	status := runActionCommand(t, command, "status", "--state", stateDir)
	if status.ConsequenceCount != 0 {
		t.Fatalf("unsigned request executed a consequence: %#v", status)
	}
}

func buildWalkthrough(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "aauth-local")
	command := exec.Command("go", "build", "-o", path, ".")
	command.Dir = "."
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("build walkthrough: %v\n%s", err, output)
	}
	return path
}

func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

type runningProcess struct {
	command  *exec.Cmd
	done     chan struct{}
	stopOnce sync.Once
}

func start(t *testing.T, command string, arguments ...string) *runningProcess {
	t.Helper()
	cmd := exec.Command(command, arguments...)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	process := &runningProcess{command: cmd, done: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		close(process.done)
	}()
	t.Cleanup(func() {
		stop(t, process)
	})
	return process
}

func stop(t *testing.T, process *runningProcess) {
	t.Helper()
	if process == nil || process.command == nil || process.command.Process == nil {
		return
	}
	process.stopOnce.Do(func() {
		select {
		case <-process.done:
			return
		default:
		}
		if err := process.command.Process.Signal(os.Interrupt); err != nil && !errors.Is(err, os.ErrProcessDone) {
			t.Fatal(err)
		}
		select {
		case <-process.done:
		case <-time.After(5 * time.Second):
			_ = process.command.Process.Kill()
			<-process.done
		}
	})
}

func waitForHealth(t *testing.T, stateDir, host, address string) {
	t.Helper()
	client := walkthroughHTTPClient(t, stateDir, host, address)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get("https://" + host + "/health")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("%s at %s did not become healthy", host, address)
}

func walkthroughHTTPClient(t *testing.T, stateDir, host, address string) *http.Client {
	t.Helper()
	certificate, err := os.ReadFile(filepath.Join(stateDir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		t.Fatal("walkthrough CA is invalid")
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return dialer.Dial("tcp", address)
		},
	}
	_ = host
	return &http.Client{Transport: transport, Timeout: 2 * time.Second}
}

func runAction(t *testing.T, command, stateDir, requestKey string) actionResult {
	t.Helper()
	return runActionCommand(t, command, "act", "--state", stateDir, "--request-key", requestKey)
}

func runActionCommand(t *testing.T, command string, arguments ...string) actionResult {
	t.Helper()
	output := run(t, command, arguments...)
	var result actionResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("decode %v output %q: %v", arguments, output, err)
	}
	return result
}

func run(t *testing.T, command string, arguments ...string) string {
	t.Helper()
	output, err := runFail(command, arguments...)
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", command, strings.Join(arguments, " "), err, output)
	}
	return output
}

func runFail(command string, arguments ...string) (string, error) {
	process := exec.Command(command, arguments...)
	var output bytes.Buffer
	process.Stdout = &output
	process.Stderr = &output
	err := process.Run()
	return output.String(), err
}
