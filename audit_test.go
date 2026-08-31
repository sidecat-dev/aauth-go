package aauth_test

import (
	"encoding/json"
	"strings"
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestEncodeAuditProducesDeterministicSourceShapedDocument(t *testing.T) {
	t.Parallel()

	missionS256 := aauth.MissionS256([]byte("approved mission"))
	entry := aauth.AuditEntry{
		MissionS256: missionS256,
		Action:      "WebSearch",
		Description: "Searched for **flights** to Tokyo in May.",
		Parameters:  json.RawMessage(`{ "query": "flights to Tokyo May 2026" }`),
		Result:      json.RawMessage(`{"status":"completed","summary":"Found 12 flight options"}`),
	}
	document, err := aauth.EncodeAudit(entry)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"mission_s256":"` + missionS256 + `","action":"WebSearch","description":"Searched for **flights** to Tokyo in May.","parameters":{"query":"flights to Tokyo May 2026"},"result":{"status":"completed","summary":"Found 12 flight options"}}`
	if string(document.ExactJSON) != want {
		t.Fatalf("audit JSON = %s, want %s", document.ExactJSON, want)
	}
	if document.Entry.MissionS256 != missionS256 || document.Entry.Action != entry.Action ||
		document.Entry.Description != entry.Description ||
		string(document.Entry.Parameters) != `{"query":"flights to Tokyo May 2026"}` ||
		string(document.Entry.Result) != `{"status":"completed","summary":"Found 12 flight options"}` {
		t.Fatalf("audit entry = %#v", document.Entry)
	}

	entry.Parameters[0] = '['
	entry.Result[0] = '['
	if document.ExactJSON[0] != '{' || document.Entry.Parameters[0] != '{' || document.Entry.Result[0] != '{' {
		t.Fatal("encoded audit aliases caller-owned input")
	}
}

func TestEncodeAuditOmitsOptionalMembers(t *testing.T) {
	t.Parallel()

	missionS256 := aauth.MissionS256([]byte("minimal mission"))
	document, err := aauth.EncodeAudit(aauth.AuditEntry{
		MissionS256: missionS256,
		Action:      "files.write",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"mission_s256":"` + missionS256 + `","action":"files.write"}`
	if string(document.ExactJSON) != want {
		t.Fatalf("minimal audit JSON = %s, want %s", document.ExactJSON, want)
	}
}

func TestDecodeAuditPreservesExactBytesAndAdditiveMembers(t *testing.T) {
	t.Parallel()

	missionS256 := aauth.MissionS256([]byte("decoded mission"))
	exact := []byte("{\n" +
		`  "mission_s256": "` + missionS256 + `",` + "\n" +
		`  "action": "messages.send",` + "\n" +
		`  "description": "Sent the reviewed **summary**.",` + "\n" +
		`  "parameters": {"channel":"review"},` + "\n" +
		`  "result": {"delivered":true},` + "\n" +
		`  "extension": {"retained":[1,2,3]}` + "\n" +
		"}")
	wantExact := append([]byte(nil), exact...)
	document, err := aauth.DecodeAudit(exact)
	if err != nil {
		t.Fatal(err)
	}
	exact[0] = '['
	if string(document.ExactJSON) != string(wantExact) {
		t.Fatalf("exact audit JSON changed: %q", document.ExactJSON)
	}
	if document.Entry.MissionS256 != missionS256 || document.Entry.Action != "messages.send" ||
		document.Entry.Description != "Sent the reviewed **summary**." ||
		string(document.Entry.Parameters) != `{"channel":"review"}` ||
		string(document.Entry.Result) != `{"delivered":true}` {
		t.Fatalf("decoded audit entry = %#v", document.Entry)
	}

	document.ExactJSON[0] = '['
	if document.Entry.Parameters[0] != '{' || document.Entry.Result[0] != '{' {
		t.Fatal("decoded entry aliases its exact document bytes")
	}
}

func TestAuditEntryValidationRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	valid := aauth.AuditEntry{
		MissionS256: aauth.MissionS256([]byte("mission")),
		Action:      "WebSearch",
		Description: "Searched the reviewed sources.",
		Parameters:  json.RawMessage(`{"query":"AAuth"}`),
		Result:      json.RawMessage(`{"count":3}`),
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name   string
		change func(*aauth.AuditEntry)
	}{
		{name: "missing mission", change: func(entry *aauth.AuditEntry) { entry.MissionS256 = "" }},
		{name: "padded mission", change: func(entry *aauth.AuditEntry) { entry.MissionS256 += "=" }},
		{name: "missing action", change: func(entry *aauth.AuditEntry) { entry.Action = "" }},
		{name: "blank action", change: func(entry *aauth.AuditEntry) { entry.Action = " \t\n" }},
		{name: "invalid action UTF-8", change: func(entry *aauth.AuditEntry) { entry.Action = string([]byte{0xff}) }},
		{name: "invalid description UTF-8", change: func(entry *aauth.AuditEntry) { entry.Description = string([]byte{0xff}) }},
		{name: "malformed parameters", change: func(entry *aauth.AuditEntry) { entry.Parameters = json.RawMessage(`{"x":`) }},
		{name: "null parameters", change: func(entry *aauth.AuditEntry) { entry.Parameters = json.RawMessage(`null`) }},
		{name: "array parameters", change: func(entry *aauth.AuditEntry) { entry.Parameters = json.RawMessage(`[]`) }},
		{name: "scalar parameters", change: func(entry *aauth.AuditEntry) { entry.Parameters = json.RawMessage(`true`) }},
		{name: "duplicate parameter member", change: func(entry *aauth.AuditEntry) { entry.Parameters = json.RawMessage(`{"x":1,"x":2}`) }},
		{name: "malformed result", change: func(entry *aauth.AuditEntry) { entry.Result = json.RawMessage(`{"ok":`) }},
		{name: "null result", change: func(entry *aauth.AuditEntry) { entry.Result = json.RawMessage(`null`) }},
		{name: "array result", change: func(entry *aauth.AuditEntry) { entry.Result = json.RawMessage(`[]`) }},
		{name: "scalar result", change: func(entry *aauth.AuditEntry) { entry.Result = json.RawMessage(`"done"`) }},
		{name: "duplicate result member", change: func(entry *aauth.AuditEntry) { entry.Result = json.RawMessage(`{"ok":true,"ok":false}`) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			entry := valid
			entry.Parameters = append(json.RawMessage(nil), valid.Parameters...)
			entry.Result = append(json.RawMessage(nil), valid.Result...)
			test.change(&entry)
			if err := entry.Validate(); err == nil {
				t.Fatalf("invalid audit entry was accepted: %#v", entry)
			}
			if _, err := aauth.EncodeAudit(entry); err == nil {
				t.Fatalf("invalid audit entry was encoded: %#v", entry)
			}
		})
	}
}

func TestDecodeAuditRejectsMalformedOrAmbiguousDocuments(t *testing.T) {
	t.Parallel()

	missionS256 := aauth.MissionS256([]byte("mission"))
	validPrefix := `{"mission_s256":"` + missionS256 + `","action":"read"`
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "not an object", body: `[]`},
		{name: "malformed JSON", body: validPrefix},
		{name: "trailing JSON", body: validPrefix + `}{}`},
		{name: "duplicate top-level member", body: `{"mission_s256":"` + missionS256 + `","action":"read","action":"write"}`},
		{name: "case variant mission", body: `{"Mission_S256":"` + missionS256 + `","action":"read"}`},
		{name: "case variant action", body: `{"mission_s256":"` + missionS256 + `","Action":"read"}`},
		{name: "case variant parameters", body: validPrefix + `,"Parameters":{}}`},
		{name: "case variant result", body: validPrefix + `,"Result":{}}`},
		{name: "null description", body: validPrefix + `,"description":null}`},
		{name: "duplicate nested member", body: validPrefix + `,"parameters":{"x":1,"x":2}}`},
		{name: "missing mission", body: `{"action":"read"}`},
		{name: "missing action", body: `{"mission_s256":"` + missionS256 + `"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := aauth.DecodeAudit([]byte(test.body)); err == nil {
				t.Fatalf("invalid audit document was accepted: %s", test.body)
			}
		})
	}
}

func TestDecodeAuditRejectsInvalidUTF8BeforeParsing(t *testing.T) {
	t.Parallel()

	missionS256 := aauth.MissionS256([]byte("mission"))
	exact := append([]byte(`{"mission_s256":"`+missionS256+`","action":"`), 0xff)
	exact = append(exact, []byte(`"}`)...)
	if _, err := aauth.DecodeAudit(exact); err == nil {
		t.Fatal("DecodeAudit accepted invalid UTF-8 exact JSON")
	}
}

func TestDecodeAuditReturnsCallerOwnedRawValues(t *testing.T) {
	t.Parallel()

	missionS256 := aauth.MissionS256([]byte("owned mission"))
	document, err := aauth.DecodeAudit([]byte(`{"mission_s256":"` + missionS256 + `","action":"read","parameters":{"nested":{"value":1}},"result":{"ok":true}}`))
	if err != nil {
		t.Fatal(err)
	}
	parametersBefore := append([]byte(nil), document.Entry.Parameters...)
	resultBefore := append([]byte(nil), document.Entry.Result...)
	document.ExactJSON = append(document.ExactJSON[:0], strings.Repeat("x", len(document.ExactJSON))...)
	if string(document.Entry.Parameters) != string(parametersBefore) || string(document.Entry.Result) != string(resultBefore) {
		t.Fatal("decoded raw values changed when caller modified ExactJSON")
	}
}
