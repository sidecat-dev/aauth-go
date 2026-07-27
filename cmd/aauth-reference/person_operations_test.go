package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestPersonTLSIdentityMustBeCurrentlyValid(t *testing.T) {
	tempDir := t.TempDir()
	certificatePath, privateKeyPath, _ := writeProcessTestTLSIdentity(
		t,
		tempDir,
		"person.example",
	)
	certificate, err := tls.LoadX509KeyPair(certificatePath, privateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := validateTLSIdentity(
		"https://person.example",
		certificate,
		now,
	); err != nil {
		t.Fatalf("current identity rejected: %v", err)
	}
	if _, err := validateTLSIdentity(
		"https://person.example",
		certificate,
		now.Add(48*time.Hour),
	); err == nil {
		t.Fatal("expired TLS identity accepted")
	}
	if _, err := validateTLSIdentity(
		"https://person.example",
		certificate,
		now.Add(-48*time.Hour),
	); err == nil {
		t.Fatal("not-yet-valid TLS identity accepted")
	}
}

func TestPersonDiagnosisUsesServerCompositionWithoutExposingCustody(t *testing.T) {
	tempDir := t.TempDir()
	apKey, _ := processTestSigningKey(t, "diagnostic-ap")
	personKey, personPrivate := processTestSigningKey(t, "diagnostic-person")
	certificatePath, tlsKeyPath, _ := writeProcessTestTLSIdentity(
		t,
		tempDir,
		"person.example",
	)
	governancePath := filepath.Join(tempDir, "state", "person-governance.json")
	profilePath := filepath.Join(tempDir, "person-profile.json")
	writeProcessTestJSON(t, profilePath, map[string]any{
		"format":          personProfileFormat,
		"identifier":      "https://person.example",
		"listen":          "127.0.0.1:8443",
		"key_id":          personKey.ID(),
		"signing_key":     []byte(personPrivate),
		"tls_certificate": certificatePath,
		"tls_private_key": tlsKeyPath,
		"governance_file": governancePath,
		"trusted_keys": map[string][]aauth.JWK{
			"https://ap.example": {apKey.PublicJWK()},
		},
		"allowed_actions": []string{"store.backup.create"},
		"allowed_scopes":  []string{"backup:write"},
	}, 0o600)

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"diagnose", "person", "--profile", profilePath},
		&stdout,
		&stderr,
	)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("diagnosis exit/stderr = %d/%q", code, stderr.String())
	}
	var result personDiagnostic
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode diagnosis %q: %v", stdout.String(), err)
	}
	if result.Schema != personDiagnosticFormat ||
		result.Status != "valid" ||
		result.Identifier != "https://person.example" ||
		result.Listen != "127.0.0.1:8443" ||
		result.KeyID != personKey.ID() ||
		result.KeyThumbprint == "" ||
		result.TrustedIssuerCount != 1 ||
		result.AllowedActionCount != 1 ||
		result.AllowedScopeCount != 1 ||
		result.GovernanceState != "new" ||
		result.TLSNotBefore == "" ||
		result.TLSNotAfter == "" {
		t.Fatalf("diagnosis = %#v", result)
	}
	output := stdout.String()
	for _, protected := range []string{
		tempDir,
		base64.StdEncoding.EncodeToString(personPrivate),
		"signing_key",
		"tls_private_key",
		"governance_file",
	} {
		if strings.Contains(output, protected) {
			t.Fatalf("diagnosis exposed protected value %q: %s", protected, output)
		}
	}
}

func TestPersonDiagnosisRejectsCorruptGovernance(t *testing.T) {
	tempDir := t.TempDir()
	apKey, _ := processTestSigningKey(t, "corrupt-ap")
	personKey, personPrivate := processTestSigningKey(t, "corrupt-person")
	certificatePath, tlsKeyPath, _ := writeProcessTestTLSIdentity(
		t,
		tempDir,
		"person.example",
	)
	governancePath := filepath.Join(tempDir, "person-governance.json")
	writeProcessTestFile(t, governancePath, []byte(`{"not":"governance"}`), 0o600)
	profilePath := filepath.Join(tempDir, "person-profile.json")
	writeProcessTestJSON(t, profilePath, map[string]any{
		"format":          personProfileFormat,
		"identifier":      "https://person.example",
		"listen":          "127.0.0.1:8443",
		"key_id":          personKey.ID(),
		"signing_key":     []byte(personPrivate),
		"tls_certificate": certificatePath,
		"tls_private_key": tlsKeyPath,
		"governance_file": governancePath,
		"trusted_keys": map[string][]aauth.JWK{
			"https://ap.example": {apKey.PublicJWK()},
		},
		"allowed_actions": []string{"store.backup.create"},
	}, 0o600)

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"diagnose", "person", "--profile", profilePath},
		&stdout,
		&stderr,
	)
	if code != 1 || stdout.Len() != 0 ||
		!strings.Contains(stderr.String(), "person diagnosis failed") {
		t.Fatalf(
			"corrupt diagnosis exit/stdout/stderr = %d/%q/%q",
			code,
			stdout.String(),
			stderr.String(),
		)
	}
	if strings.Contains(stderr.String(), base64.StdEncoding.EncodeToString(personPrivate)) {
		t.Fatalf("diagnosis error exposed signing key: %s", stderr.String())
	}
}

func TestPersonDemoRunsInstalledProcessJourney(t *testing.T) {
	tempDir := t.TempDir()
	binary := filepath.Join(tempDir, "aauth-reference")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build aauth-reference: %v\n%s", err, output)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "demo", "person")
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("run person demo: %v\nstderr:\n%s", err, stderr.String())
	}
	if ctx.Err() != nil || stderr.Len() != 0 {
		t.Fatalf("demo context/stderr = %v/%q", ctx.Err(), stderr.String())
	}
	var result personDemoResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode demo %q: %v", stdout.String(), err)
	}
	if result.Schema != personDemoFormat ||
		result.Status != "verified" ||
		!result.MissionCreated ||
		!result.PermissionGranted ||
		!result.AuditRecorded ||
		!result.UnlistedActionDenied ||
		!result.RestartRecovered ||
		!result.GovernancePersisted {
		t.Fatalf("demo result = %#v", result)
	}
	if strings.Contains(stdout.String(), tempDir) ||
		strings.Contains(stdout.String(), "signing_key") {
		t.Fatalf("demo exposed temporary custody: %s", stdout.String())
	}
}
