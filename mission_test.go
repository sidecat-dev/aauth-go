package aauth_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
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

func TestApprovedMissionMatchesOnlyExactApprovedToolNames(t *testing.T) {
	t.Parallel()

	mission, err := aauth.EncodeMission(aauth.MissionBlob{
		Approver:    "https://person.example",
		Agent:       "aauth:planner@agents.example",
		ApprovedAt:  time.Date(2026, 9, 1, 18, 0, 0, 0, time.UTC),
		Description: "Read the reviewed report inputs.",
		ApprovedTools: []aauth.MissionTool{
			{Name: "Read", Description: "Read reviewed inputs"},
			{Name: "Summarize", Description: "Summarize the inputs"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name string
		want bool
	}{
		{name: "Read", want: true},
		{name: "Summarize", want: true},
		{name: "read", want: false},
		{name: " Read", want: false},
		{name: "", want: false},
		{name: "Publish", want: false},
	} {
		if got := mission.ApprovesTool(test.name); got != test.want {
			t.Errorf("ApprovesTool(%q) = %t, want %t", test.name, got, test.want)
		}
	}

	var zero aauth.ApprovedMission
	if zero.ApprovesTool("Read") {
		t.Fatal("zero mission approved a tool")
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

func TestMissionUpdatePreservesExactDocument(t *testing.T) {
	t.Parallel()

	exact := []byte("{\n  \"action\": \"update\",\n  \"description\": \"Use the reviewed source\",\n  \"extension\": {\"retained\": true}\n}")
	wantExact := append([]byte(nil), exact...)
	s256 := aauth.MissionS256(exact)
	document, err := aauth.DecodeMissionUpdate(s256, exact)
	if err != nil {
		t.Fatal(err)
	}
	exact[0] = '['
	if document.S256 != s256 || string(document.ExactJSON) != string(wantExact) ||
		document.Update.Action != "update" || document.Update.Description != "Use the reviewed source" {
		t.Fatalf("decoded update = %#v", document)
	}

	encoded, err := aauth.EncodeMissionUpdate(aauth.MissionUpdate{
		Action: "update", Description: "Use the reviewed source",
	})
	if err != nil {
		t.Fatal(err)
	}
	wantWire := `{"action":"update","description":"Use the reviewed source"}`
	if string(encoded.ExactJSON) != wantWire || encoded.S256 != aauth.MissionS256(encoded.ExactJSON) {
		t.Fatalf("encoded update = %#v", encoded)
	}
}

func TestMissionUpdateRejectsInvalidDocuments(t *testing.T) {
	t.Parallel()

	valid := []byte(`{"action":"update","description":"Changed work"}`)
	for _, test := range []struct {
		name string
		s256 string
		body []byte
	}{
		{name: "substituted digest", s256: aauth.MissionS256([]byte("other")), body: valid},
		{name: "wrong action", body: []byte(`{"action":"completion","description":"Changed work"}`)},
		{name: "missing action", body: []byte(`{"description":"Changed work"}`)},
		{name: "missing description", body: []byte(`{"action":"update"}`)},
		{name: "empty description", body: []byte(`{"action":"update","description":""}`)},
		{name: "case variant", body: []byte(`{"Action":"update","description":"Changed work"}`)},
		{name: "duplicate member", body: []byte(`{"action":"update","action":"update","description":"Changed work"}`)},
		{name: "trailing JSON", body: []byte(`{"action":"update","description":"Changed work"}{}`)},
		{name: "malformed JSON", body: []byte(`{"action":"update"`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			s256 := test.s256
			if s256 == "" {
				s256 = aauth.MissionS256(test.body)
			}
			if _, err := aauth.DecodeMissionUpdate(s256, test.body); err == nil {
				t.Fatal("invalid mission update was accepted")
			}
		})
	}

	for _, update := range []aauth.MissionUpdate{
		{},
		{Action: "completion", Description: "Changed work"},
		{Action: "update"},
	} {
		if _, err := aauth.EncodeMissionUpdate(update); err == nil {
			t.Fatalf("invalid update was encoded: %#v", update)
		}
	}
}

func TestMissionCompletionPreservesExactDocument(t *testing.T) {
	t.Parallel()

	exact := []byte("{\n  \"action\": \"completion\",\n  \"summary\": \"Published the reviewed report\",\n  \"extension\": [1, 2, 3]\n}")
	wantExact := append([]byte(nil), exact...)
	document, err := aauth.DecodeMissionCompletion(exact)
	if err != nil {
		t.Fatal(err)
	}
	exact[0] = '['
	if string(document.ExactJSON) != string(wantExact) ||
		document.Completion.Action != "completion" || document.Completion.Summary != "Published the reviewed report" {
		t.Fatalf("decoded completion = %#v", document)
	}

	encoded, err := aauth.EncodeMissionCompletion(aauth.MissionCompletion{
		Action: "completion", Summary: "Published the reviewed report",
	})
	if err != nil {
		t.Fatal(err)
	}
	wantWire := `{"action":"completion","summary":"Published the reviewed report"}`
	if string(encoded.ExactJSON) != wantWire {
		t.Fatalf("encoded completion = %#v", encoded)
	}
}

func TestMissionCompletionRejectsInvalidDocuments(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		body []byte
	}{
		{name: "wrong action", body: []byte(`{"action":"update","summary":"Work complete"}`)},
		{name: "missing action", body: []byte(`{"summary":"Work complete"}`)},
		{name: "missing summary", body: []byte(`{"action":"completion"}`)},
		{name: "empty summary", body: []byte(`{"action":"completion","summary":""}`)},
		{name: "case variant", body: []byte(`{"action":"completion","Summary":"Work complete"}`)},
		{name: "duplicate member", body: []byte(`{"action":"completion","summary":"one","summary":"two"}`)},
		{name: "trailing JSON", body: []byte(`{"action":"completion","summary":"Work complete"}[]`)},
		{name: "malformed JSON", body: []byte(`{"action":"completion"`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := aauth.DecodeMissionCompletion(test.body); err == nil {
				t.Fatal("invalid mission completion was accepted")
			}
		})
	}

	for _, completion := range []aauth.MissionCompletion{
		{},
		{Action: "update", Summary: "Work complete"},
		{Action: "completion"},
	} {
		if _, err := aauth.EncodeMissionCompletion(completion); err == nil {
			t.Fatalf("invalid completion was encoded: %#v", completion)
		}
	}
}

func TestMissionUpdateResponseWireShape(t *testing.T) {
	t.Parallel()

	wire, err := json.Marshal(aauth.MissionUpdateResponse{S256: strings.Repeat("A", 43)})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"s256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`
	if string(wire) != want {
		t.Fatalf("mission update response JSON = %s, want %s", wire, want)
	}
}
