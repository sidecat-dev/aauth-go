package aauth_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	aauth "aauth-go"
)

func TestMissionApprovalPreservesAndVerifiesExactBlob(t *testing.T) {
	t.Parallel()

	approvedAt := time.Date(2026, 8, 30, 20, 15, 0, 0, time.UTC)
	expiresAt := approvedAt.Add(2 * time.Hour)
	mission, err := aauth.EncodeMission(aauth.MissionBlob{
		Approver:    "https://person.example",
		Agent:       "aauth:planner@agents.example",
		ApprovedAt:  approvedAt,
		ExpiresAt:   &expiresAt,
		Description: "# Publish the report\n\nPrepare and publish the reviewed report.",
		ApprovedTools: []aauth.MissionTool{{
			Name: "Publish", Description: "Publish the reviewed report",
		}},
		ApprovedResources: []string{"https://reports.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if mission.S256 != aauth.MissionS256(mission.ExactJSON) {
		t.Fatalf("mission s256 = %q", mission.S256)
	}
	if got := base64.RawURLEncoding.EncodeToString(mission.ExactJSON); got != mission.Encoded {
		t.Fatalf("encoded mission = %q, want %q", mission.Encoded, got)
	}

	decoded, err := aauth.DecodeMission(mission.S256, mission.Encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded.ExactJSON) != string(mission.ExactJSON) || decoded.S256 != mission.S256 || decoded.Encoded != mission.Encoded {
		t.Fatalf("decoded mission = %#v, want exact bytes %q", decoded, mission.ExactJSON)
	}
	if decoded.Blob.Approver != "https://person.example" || decoded.Blob.Agent != "aauth:planner@agents.example" ||
		!decoded.Blob.ApprovedAt.Equal(approvedAt) || decoded.Blob.ExpiresAt == nil || !decoded.Blob.ExpiresAt.Equal(expiresAt) ||
		decoded.Blob.Description != "# Publish the report\n\nPrepare and publish the reviewed report." {
		t.Fatalf("decoded blob = %#v", decoded.Blob)
	}
}

func TestEncodeMissionDoesNotAliasCallerValues(t *testing.T) {
	t.Parallel()

	expiresAt := time.Date(2026, 8, 30, 21, 0, 0, 0, time.UTC)
	wantExpiry := expiresAt
	blob := aauth.MissionBlob{
		Approver: "https://person.example", Agent: "aauth:planner@agents.example",
		ApprovedAt: expiresAt.Add(-time.Hour), ExpiresAt: &expiresAt, Description: "Work",
		ApprovedTools:     []aauth.MissionTool{{Name: "Read", Description: "Read inputs"}},
		ApprovedResources: []string{"https://resource.example"},
	}
	mission, err := aauth.EncodeMission(blob)
	if err != nil {
		t.Fatal(err)
	}
	blob.ApprovedTools[0].Name = "Changed"
	blob.ApprovedResources[0] = "https://other.example"
	*blob.ExpiresAt = expiresAt.Add(time.Hour)
	if mission.Blob.ApprovedTools[0].Name != "Read" || mission.Blob.ApprovedResources[0] != "https://resource.example" ||
		mission.Blob.ExpiresAt == nil || !mission.Blob.ExpiresAt.Equal(wantExpiry) {
		t.Fatalf("encoded mission aliased caller values: %#v", mission.Blob)
	}
}

func TestDecodeMissionRejectsSubstitutionAndMalformedBlob(t *testing.T) {
	t.Parallel()

	valid := []byte(`{"approver":"https://person.example","agent":"aauth:planner@agents.example","approved_at":"2026-08-30T20:15:00Z","description":"Do the work","extension":{"retained":true}}`)
	identifier := aauth.MissionS256(valid)
	encoded := base64.RawURLEncoding.EncodeToString(valid)
	mission, err := aauth.DecodeMission(identifier, encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(mission.ExactJSON) != string(valid) {
		t.Fatalf("exact JSON changed: %q", mission.ExactJSON)
	}

	for _, test := range []struct {
		name       string
		identifier string
		encoded    string
	}{
		{name: "changed identifier", identifier: aauth.MissionS256([]byte("other")), encoded: encoded},
		{name: "padded encoding", identifier: identifier, encoded: encoded + "="},
		{name: "invalid JSON", identifier: aauth.MissionS256([]byte("not json")), encoded: base64.RawURLEncoding.EncodeToString([]byte("not json"))},
		{name: "ambiguous member", identifier: aauth.MissionS256([]byte(`{"approver":"https://person.example","Approver":"https://other.example","agent":"aauth:planner@agents.example","approved_at":"2026-08-30T20:15:00Z","description":"Do the work"}`)), encoded: base64.RawURLEncoding.EncodeToString([]byte(`{"approver":"https://person.example","Approver":"https://other.example","agent":"aauth:planner@agents.example","approved_at":"2026-08-30T20:15:00Z","description":"Do the work"}`))},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := aauth.DecodeMission(test.identifier, test.encoded); err == nil {
				t.Fatal("invalid mission was accepted")
			}
		})
	}
}

func TestMissionValuesValidateOnlyProtocolConstraints(t *testing.T) {
	t.Parallel()

	validProposal := aauth.MissionProposal{
		Description: "Prepare the report",
		Tools:       []aauth.MissionTool{{Name: "Read", Description: "Read source material"}},
		Resources:   []string{"https://reports.example"},
	}
	if err := validProposal.Validate(); err != nil {
		t.Fatal(err)
	}

	invalidProposals := []aauth.MissionProposal{
		{},
		{Description: "Prepare the report", Resources: []string{"http://reports.example"}},
	}
	for _, proposal := range invalidProposals {
		if err := proposal.Validate(); err == nil {
			t.Fatalf("invalid proposal was accepted: %#v", proposal)
		}
	}

	approvedAt := time.Date(2026, 8, 30, 20, 15, 0, 0, time.UTC)
	validBlob := aauth.MissionBlob{
		Approver: "https://person.example", Agent: "aauth:planner@agents.example",
		ApprovedAt: approvedAt, Description: "Prepare the report",
	}
	if _, err := aauth.EncodeMission(validBlob); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*aauth.MissionBlob){
		func(blob *aauth.MissionBlob) { blob.Approver = "" },
		func(blob *aauth.MissionBlob) { blob.Agent = "" },
		func(blob *aauth.MissionBlob) { blob.ApprovedAt = time.Time{} },
		func(blob *aauth.MissionBlob) { blob.Description = "" },
		func(blob *aauth.MissionBlob) { blob.ApprovedResources = []string{"not a URL"} },
	} {
		blob := validBlob
		change(&blob)
		if _, err := aauth.EncodeMission(blob); err == nil {
			t.Fatalf("invalid blob was accepted: %#v", blob)
		}
	}
}

func TestMissionApprovalWireShape(t *testing.T) {
	t.Parallel()

	approval := aauth.MissionApproval{
		S256:         strings.Repeat("A", 43),
		Mission:      "e30",
		Capabilities: []string{"interaction"},
		PersonTokens: map[string]string{"https://resource.example": "token"},
	}
	wire, err := json.Marshal(approval)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"s256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","mission":"e30","capabilities":["interaction"],"person_tokens":{"https://resource.example":"token"}}`
	if string(wire) != want {
		t.Fatalf("approval JSON = %s, want %s", wire, want)
	}
}
