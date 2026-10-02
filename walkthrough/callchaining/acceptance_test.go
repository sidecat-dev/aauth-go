package main

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// This catches a broken network composition: wrong directed person, original
// caller key reused downstream, missing expiry bound, or dispatch after refusal.
// It runs four real TLS servers in child processes and a separate CLI caller.
func TestTLSProcessCallChain(t *testing.T) {
	binary := os.Getenv("AAUTH_CALLCHAIN_BINARY")
	if binary == "" {
		binary = filepath.Join(t.TempDir(), "aauth-callchain")
		cmd := exec.Command("go", "build", "-p=1", "-o", binary, ".")
		cmd.Env = append(os.Environ(), "GOWORK=off")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build consumer: %v\n%s", err, output)
		}
	}
	state := t.TempDir()
	initialized := commandJSON(t, binary, "init", "--state", state,
		"--agent-address", freeAddress(t), "--person-address", freeAddress(t),
		"--orders-address", freeAddress(t), "--inventory-address", freeAddress(t))
	expectedKey := initialized["intermediary_key"]
	if expectedKey == nil || expectedKey == "" {
		t.Fatal("init did not identify the public intermediary proof key")
	}
	for _, role := range []string{"agent", "person", "orders", "inventory"} {
		startProcess(t, binary, "serve", "--state", state, "--role", role)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		cmd := exec.Command(binary, "status", "--state", state)
		if _, err := cmd.CombinedOutput(); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("four TLS roles did not become reachable")
		}
		time.Sleep(50 * time.Millisecond)
	}
	unsigned := commandJSON(t, binary, "probe", "--state", state, "--kind", "unsigned")
	if unsigned["status"] != "refused" || unsigned["http_status"] != float64(401) {
		t.Fatalf("unsigned request was not refused: %v", unsigned)
	}
	assertCount(t, commandJSON(t, binary, "status", "--state", state), 0)
	result := commandJSON(t, binary, "call", "--state", state)
	if result["status"] != "completed" || result["orders_subject"] != "person-at-orders" ||
		result["inventory_subject"] != "person-at-inventory" || result["scope"] != "inventory.reserve" ||
		result["intermediary_key"] != expectedKey || result["consequence_count"] != float64(1) {
		t.Fatalf("wrong downstream action or authority: %v", result)
	}
	upstreamExp, ok := result["upstream_exp"].(float64)
	if !ok {
		t.Fatalf("missing upstream expiry: %v", result)
	}
	personExp, personOK := result["downstream_person_exp"].(float64)
	authExp, authOK := result["downstream_auth_exp"].(float64)
	if !personOK || !authOK || personExp > upstreamExp || authExp > upstreamExp || authExp <= float64(time.Now().Unix()) {
		t.Fatalf("downstream credentials are not live and bounded: %v", result)
	}
	status := commandJSON(t, binary, "status", "--state", state)
	assertCount(t, status, 1)
	for _, role := range []string{"agent", "person", "orders", "inventory"} {
		observed, ok := status[role].(map[string]any)
		if !ok || observed["metadata_requests"].(float64) < 1 || observed["jwks_requests"].(float64) < 1 {
			t.Fatalf("%s discovery did not cross the socket boundary: %v", role, status)
		}
	}
	// Natural expiry: no clock override and no reminting an expired fixture.
	remaining := time.Until(time.Unix(int64(upstreamExp)+1, 0))
	if remaining > 30*time.Second {
		t.Fatalf("demo credential expiry is not bounded: wait %s", remaining)
	}
	if remaining > 0 {
		time.Sleep(remaining)
	}
	expired := commandJSON(t, binary, "probe", "--state", state, "--kind", "expired")
	if expired["status"] != "refused" || expired["http_status"] != float64(401) || expired["signature_error"] != "error=expired_jwt" {
		t.Fatalf("expired credential was not refused by Orders: %v", expired)
	}
	assertCount(t, commandJSON(t, binary, "status", "--state", state), 1)
	t.Logf("observed authorized action and two refusals over TLS: %v", result)
}

func assertCount(t *testing.T, status map[string]any, want float64) {
	t.Helper()
	if status["consequence_count"] != want {
		t.Fatalf("inventory actions = %v, want %v", status["consequence_count"], want)
	}
}

func commandJSON(t *testing.T, binary string, arguments ...string) map[string]any {
	t.Helper()
	output, err := exec.Command(binary, arguments...).CombinedOutput()
	if err != nil {
		t.Fatalf("command %v: %v\n%s", arguments, err, output)
	}
	var result map[string]any
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("command %v returned non-JSON: %v\n%s", arguments, err, output)
	}
	return result
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

type processLog struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (log *processLog) Write(value []byte) (int, error) {
	log.mu.Lock()
	defer log.mu.Unlock()
	return log.buffer.Write(value)
}

func (log *processLog) text() string {
	log.mu.Lock()
	defer log.mu.Unlock()
	return log.buffer.String()
}

func startProcess(t *testing.T, binary string, arguments ...string) {
	t.Helper()
	cmd := exec.Command(binary, arguments...)
	log := &processLog{}
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("role %v stopped with %v: %s", arguments, err, log.text())
			}
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
			t.Errorf("role %v did not stop on interrupt: %s", arguments, log.text())
		}
	})
}
