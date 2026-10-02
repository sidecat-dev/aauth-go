package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type connectionResult struct {
	Status      string `json:"status"`
	Agent       string `json:"agent"`
	TokenSHA256 string `json:"token_sha256"`
}

func TestHostedWalkthroughEnrollsAcrossTLSAndRecoversAfterRestart(t *testing.T) {
	hostState := t.TempDir()
	agentState := t.TempDir()
	command := buildHostedWalkthrough(t)
	address := hostedFreeAddress(t)

	hostedRun(t, command, "host-init", "--state", hostState, "--listen", address, "--origin", "https://hosted.test")
	hostedRun(t, command, "agent-init", "--state", agentState, "--bootstrap", filepath.Join(hostState, "bootstrap.json"), "--service-address", address)

	service := hostedStart(t, command, "serve", "--state", hostState)
	hostedWaitForService(t, command, agentState)
	first := hostedConnect(t, command, agentState)
	if first.Status != "connected" || first.Agent != "aauth:agent-1@hosted.test" || first.TokenSHA256 == "" {
		t.Fatalf("first connection = %#v", first)
	}

	hostedStop(t, service)
	if err := os.Remove(filepath.Join(agentState, "connection-result.json")); err != nil {
		t.Fatal(err)
	}
	service = hostedStart(t, command, "serve", "--state", hostState)
	t.Cleanup(func() { hostedStop(t, service) })
	hostedWaitForService(t, command, agentState)
	recovered := hostedConnect(t, command, agentState)
	if recovered != first {
		t.Fatalf("recovered connection = %#v, want %#v", recovered, first)
	}

	statusOutput := hostedRun(t, command, "host-status", "--state", agentState)
	var status struct {
		Enrollments int `json:"enrollments"`
		Refreshes   int `json:"refreshes"`
	}
	if err := json.Unmarshal([]byte(statusOutput), &status); err != nil {
		t.Fatalf("decode host status %q: %v", statusOutput, err)
	}
	if status.Enrollments != 1 || status.Refreshes != 1 {
		t.Fatalf("host status = %#v, want one enrollment and one refresh", status)
	}
}

func TestHostedWalkthroughAuthenticatesPersonAndRetainsConnectorCredential(t *testing.T) {
	hostState := t.TempDir()
	agentState := t.TempDir()
	command := buildHostedWalkthrough(t)
	address := hostedFreeAddress(t)
	hostedRun(t, command, "host-init", "--state", hostState, "--listen", address, "--origin", "https://hosted.test")
	hostedRun(t, command, "agent-init", "--state", agentState, "--bootstrap", filepath.Join(hostState, "bootstrap.json"), "--service-address", address)
	service := hostedStart(t, command, "serve", "--state", hostState)
	hostedWaitForService(t, command, agentState)
	output, err := hostedRunFail(command, "link", "--state", agentState, "--account", "records-primary")
	if err == nil || !strings.Contains(output, "login_required") {
		t.Fatalf("unauthenticated link = %v, %q", err, output)
	}

	hostedRun(t, command, "login", "--state", agentState, "--email", "person@example.test", "--password-file", filepath.Join(hostState, "user-password"))
	hostedRun(t, command, "link", "--state", agentState, "--account", "records-primary")
	var retainedAccount accountStoreState
	if err := readJSON(filepath.Join(hostState, "account-store.json"), &retainedAccount); err != nil {
		t.Fatal(err)
	}
	if retainedAccount.Connector == nil || retainedAccount.Connector.Credential == "" {
		t.Fatal("host did not retain a connector credential")
	}
	hostedStop(t, service)
	service = hostedStart(t, command, "serve", "--state", hostState)
	t.Cleanup(func() { hostedStop(t, service) })
	hostedWaitForService(t, command, agentState)

	statusOutput := hostedRun(t, command, "account-status", "--state", agentState)
	if strings.Contains(statusOutput, retainedAccount.Connector.Credential) {
		t.Fatalf("account status disclosed connector credential: %s", statusOutput)
	}
	assertDirectoryOmits(t, agentState, retainedAccount.Connector.Credential)
	var status struct {
		Email   string `json:"email"`
		Account string `json:"account"`
		Linked  bool   `json:"linked"`
	}
	if err := json.Unmarshal([]byte(statusOutput), &status); err != nil {
		t.Fatalf("decode account status %q: %v", statusOutput, err)
	}
	if status.Email != "person@example.test" || status.Account != "records-primary" || !status.Linked {
		t.Fatalf("account status = %#v", status)
	}
}

func assertDirectoryOmits(t *testing.T, root, secret string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		encoded, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(encoded, []byte(secret)) {
			return fmt.Errorf("%s contains the hosted connector credential", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestHostedWalkthroughRunsMissionBudgetedConnectorAndReplaysAfterRestart(t *testing.T) {
	hostState := t.TempDir()
	agentState := t.TempDir()
	command := buildHostedWalkthrough(t)
	address := hostedFreeAddress(t)
	hostedRun(t, command, "host-init", "--state", hostState, "--listen", address, "--origin", "https://hosted.test")
	hostedRun(t, command, "agent-init", "--state", agentState, "--bootstrap", filepath.Join(hostState, "bootstrap.json"), "--service-address", address)
	service := hostedStart(t, command, "serve", "--state", hostState)
	hostedWaitForService(t, command, agentState)
	hostedConnect(t, command, agentState)
	hostedRun(t, command, "login", "--state", agentState, "--email", "person@example.test", "--password-file", filepath.Join(hostState, "user-password"))
	hostedRun(t, command, "link", "--state", agentState, "--account", "records-primary")
	hostedRun(t, command, "approve", "--state", agentState)

	firstOutput, firstErr := hostedRunFail(command, "act", "--state", agentState, "--request-key", "hosted-write-1")
	if firstErr != nil {
		protocolState, _ := os.ReadFile(filepath.Join(hostState, "protocol-store.json"))
		t.Fatalf("first hosted action: %v\n%s\nprotocol state:\n%s", firstErr, firstOutput, protocolState)
	}
	var first hostedActionResult
	if err := json.Unmarshal([]byte(firstOutput), &first); err != nil {
		t.Fatalf("decode first action %q: %v", firstOutput, err)
	}
	if first.Status != "completed" || first.Result != "record-1" || first.Replayed || first.ConnectorCalls != 1 || first.BudgetRemaining != 0 {
		t.Fatalf("first hosted action = %#v", first)
	}
	hostedStop(t, service)
	if err := os.Remove(actionResultPath(agentState, "hosted-write-1")); err != nil {
		t.Fatal(err)
	}
	service = hostedStart(t, command, "serve", "--state", hostState)
	t.Cleanup(func() { hostedStop(t, service) })
	hostedWaitForService(t, command, agentState)
	replayed := hostedAction(t, command, agentState, "hosted-write-1")
	if replayed.Status != "completed" || replayed.Result != "record-1" || !replayed.Replayed || replayed.ConnectorCalls != 1 || replayed.BudgetRemaining != 0 {
		t.Fatalf("replayed hosted action = %#v", replayed)
	}
}

func TestHostedWalkthroughRevokesBeforeTheNextConnectorDispatch(t *testing.T) {
	hostState := t.TempDir()
	agentState := t.TempDir()
	command := buildHostedWalkthrough(t)
	address := hostedFreeAddress(t)
	hostedRun(t, command, "host-init", "--state", hostState, "--listen", address, "--origin", "https://hosted.test")
	hostedRun(t, command, "agent-init", "--state", agentState, "--bootstrap", filepath.Join(hostState, "bootstrap.json"), "--service-address", address)
	service := hostedStart(t, command, "serve", "--state", hostState)
	t.Cleanup(func() { hostedStop(t, service) })
	hostedWaitForService(t, command, agentState)
	hostedConnect(t, command, agentState)
	hostedRun(t, command, "login", "--state", agentState, "--email", "person@example.test", "--password-file", filepath.Join(hostState, "user-password"))
	hostedRun(t, command, "link", "--state", agentState, "--account", "records-primary")
	hostedRun(t, command, "approve", "--state", agentState)
	hostedAction(t, command, agentState, "hosted-write-1")
	hostedRun(t, command, "revoke", "--state", agentState)

	output, err := hostedRunFail(command, "act", "--state", agentState, "--request-key", "hosted-write-2")
	if err == nil || !strings.Contains(output, "revoked_jwt") {
		t.Fatalf("post-revocation action = %v, %q", err, output)
	}
	statusOutput := hostedRun(t, command, "host-status", "--state", agentState)
	var status struct {
		ConnectorCalls int `json:"connector_calls"`
	}
	if err := json.Unmarshal([]byte(statusOutput), &status); err != nil {
		t.Fatal(err)
	}
	if status.ConnectorCalls != 1 {
		t.Fatalf("connector calls after revocation = %d, want 1", status.ConnectorCalls)
	}
}

type hostedActionResult struct {
	Status          string `json:"status"`
	Result          string `json:"result"`
	Replayed        bool   `json:"replayed"`
	ConnectorCalls  int    `json:"connector_calls"`
	BudgetRemaining int64  `json:"budget_remaining"`
}

func hostedAction(t *testing.T, command, state, requestKey string) hostedActionResult {
	t.Helper()
	output := hostedRun(t, command, "act", "--state", state, "--request-key", requestKey)
	var result hostedActionResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("decode action output %q: %v", output, err)
	}
	return result
}

func buildHostedWalkthrough(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "aauth-hosted")
	command := exec.Command("go", "build", "-o", path, ".")
	command.Dir = "."
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("build hosted walkthrough: %v\n%s", err, output)
	}
	return path
}

func hostedFreeAddress(t *testing.T) string {
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

type hostedProcess struct {
	command  *exec.Cmd
	done     chan struct{}
	stopOnce sync.Once
	output   *bytes.Buffer
}

func hostedStart(t *testing.T, command string, arguments ...string) *hostedProcess {
	t.Helper()
	cmd := exec.Command(command, arguments...)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	process := &hostedProcess{command: cmd, done: make(chan struct{}), output: &output}
	go func() {
		_ = cmd.Wait()
		close(process.done)
	}()
	t.Cleanup(func() {
		if t.Failed() && process.output.Len() != 0 {
			t.Logf("hosted process output:\n%s", process.output.String())
		}
		hostedStop(t, process)
	})
	return process
}

func hostedStop(t *testing.T, process *hostedProcess) {
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

func hostedWaitForService(t *testing.T, command, agentState string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := hostedRunFail(command, "health", "--state", agentState); err == nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("hosted service did not become healthy")
}

func hostedConnect(t *testing.T, command, state string) connectionResult {
	t.Helper()
	output := hostedRun(t, command, "connect", "--state", state)
	var result connectionResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("decode connect output %q: %v", output, err)
	}
	return result
}

func hostedRun(t *testing.T, command string, arguments ...string) string {
	t.Helper()
	output, err := hostedRunFail(command, arguments...)
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", command, strings.Join(arguments, " "), err, output)
	}
	return output
}

func hostedRunFail(command string, arguments ...string) (string, error) {
	process := exec.Command(command, arguments...)
	var output bytes.Buffer
	process.Stdout = &output
	process.Stderr = &output
	err := process.Run()
	return output.String(), err
}
