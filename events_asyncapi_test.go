package aauth

import (
	"bytes"
	"strings"
	"testing"
)

func TestEventsAsyncAPIParsesProtectedJSONMessageAndValidatesPayload(t *testing.T) {
	exact := eventsAsyncAPITestDocument()
	contract, err := ParseEventsAsyncAPI(exact)
	if err != nil {
		t.Fatal(err)
	}
	if contract.Digest() != R3S256(exact) {
		t.Fatalf("contract digest = %q, want %q", contract.Digest(), R3S256(exact))
	}
	if !bytes.Equal(contract.ExactBytes(), exact) {
		t.Fatal("contract did not preserve exact source bytes")
	}
	returned := contract.ExactBytes()
	returned[0] ^= 0xff
	if !bytes.Equal(contract.ExactBytes(), exact) {
		t.Fatal("caller mutated retained contract bytes")
	}

	message, err := contract.ProtectedMessage("subscribeProtectedWaitlist", "slotAvailable")
	if err != nil {
		t.Fatal(err)
	}
	if message.OperationID != "subscribeProtectedWaitlist" ||
		message.ChannelID != "waitlistProtected" ||
		message.MessageID != "slotAvailable" ||
		message.Address != "/appointments/waitlist/{subscriptionTicket}" ||
		message.TicketParameter != "subscriptionTicket" ||
		message.ContentType != "application/json" {
		t.Fatalf("protected message = %#v", message)
	}

	valid := []byte(`{"event_type":"slot.available","slot_time":"2026-07-15T10:00:00Z","doctor_id":"doctor-7"}`)
	if err := message.ValidatePayload(valid); err != nil {
		t.Fatalf("valid payload: %v", err)
	}
	for _, invalid := range [][]byte{
		[]byte(`{"event_type":"slot.available"}`),
		[]byte(`{"event_type":"slot.changed","slot_time":"2026-07-15T10:00:00Z"}`),
		[]byte(`{"event_type":"slot.available","slot_time":"not-a-time"}`),
		[]byte(`{"event_type":"slot.available","slot_time":"2026-07-15T10:00:00Z","extra":true}`),
		[]byte(`{"event_type":"slot.available","slot_time":"2026-07-15T10:00:00Z"} {}`),
	} {
		if err := message.ValidatePayload(invalid); err == nil {
			t.Fatalf("invalid payload accepted: %s", invalid)
		}
	}
	if err := message.ValidatePayload(nil); err == nil {
		t.Fatal("absent payload accepted for a payload-bearing message")
	}
}

func TestEventsAsyncAPIRejectsUnsupportedOrAmbiguousDocuments(t *testing.T) {
	valid := string(eventsAsyncAPITestDocument())
	for _, test := range []struct {
		name     string
		document string
	}{
		{name: "not json", document: "asyncapi: 3.0.0"},
		{name: "duplicate root name", document: strings.Replace(valid, `"asyncapi":"3.0.0",`, `"asyncapi":"3.0.0","asyncapi":"3.0.0",`, 1)},
		{name: "wrong version", document: strings.Replace(valid, `"asyncapi":"3.0.0"`, `"asyncapi":"3.1.0"`, 1)},
		{name: "missing ticket parameter", document: strings.Replace(valid, `"parameters":{"subscriptionTicket":{"description":"Single-use ticket from the protected response."}},`, `"parameters":{},`, 1)},
		{name: "ticket expression embedded in path segment", document: strings.Replace(valid, `/appointments/waitlist/{subscriptionTicket}`, `/appointments/waitlist/prefix-{subscriptionTicket}`, 1)},
		{name: "wrong action", document: strings.Replace(valid, `"action":"receive"`, `"action":"send"`, 1)},
		{name: "remote channel reference", document: strings.Replace(valid, `"$ref":"#/channels/waitlistProtected"`, `"$ref":"https://schemas.example/channels.json"`, 1)},
		{name: "remote message reference", document: strings.Replace(valid, `"$ref":"#/components/messages/SlotAvailable"`, `"$ref":"https://schemas.example/slot.json"`, 1)},
		{name: "protected operation security", document: strings.Replace(valid, `"action":"receive",`, `"action":"receive","security":[{"$ref":"#/components/securitySchemes/aauth_subscribe"}],`, 1)},
		{name: "OpenAPI security map", document: strings.Replace(valid, `"action":"receive",`, `"action":"receive","security":[{"aauth_subscribe":[]}],`, 1)},
		{name: "JWT content type", document: strings.Replace(valid, `"contentType":"application/json"`, `"contentType":"application/jwt"`, 1)},
		{name: "wrong security type", document: strings.Replace(valid, `"type":"http","scheme":"aauth-subscribe"`, `"type":"apiKey","scheme":"aauth-subscribe"`, 1)},
		{name: "wrong security scheme", document: strings.Replace(valid, `"scheme":"aauth-subscribe"`, `"scheme":"bearer"`, 1)},
		{name: "payload remote ref", document: strings.Replace(valid, `"payload":{"type":"object"`, `"payload":{"$ref":"https://schemas.example/payload.json","type":"object"`, 1)},
		{name: "ambiguous channel message", document: strings.Replace(valid, `"messages":{"slotAvailable":{"$ref":"#/components/messages/SlotAvailable"}}`, `"messages":{"slotAvailable":{"$ref":"#/components/messages/SlotAvailable"},"other":{"$ref":"#/components/messages/SlotAvailable"}}`, 1)},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseEventsAsyncAPI([]byte(test.document)); err == nil {
				t.Fatal("unsupported AsyncAPI document was accepted")
			}
		})
	}
}

func TestEventsAsyncAPISelectionIsExact(t *testing.T) {
	contract, err := ParseEventsAsyncAPI(eventsAsyncAPITestDocument())
	if err != nil {
		t.Fatal(err)
	}
	for _, selection := range [][2]string{
		{"unknownOperation", "slotAvailable"},
		{"subscribeProtectedWaitlist", "unknownMessage"},
		{"", "slotAvailable"},
		{"subscribeProtectedWaitlist", ""},
	} {
		if _, err := contract.ProtectedMessage(selection[0], selection[1]); err == nil {
			t.Fatalf("invalid selection accepted: %q/%q", selection[0], selection[1])
		}
	}
}

func eventsAsyncAPITestDocument() []byte {
	return []byte(`{
  "asyncapi":"3.0.0",
  "info":{"title":"Appointments Events","version":"1.0.0"},
  "channels":{
    "waitlistProtected":{
      "address":"/appointments/waitlist/{subscriptionTicket}",
      "description":"Ticket URL returned by a prior authenticated operation.",
      "parameters":{"subscriptionTicket":{"description":"Single-use ticket from the protected response."}},
      "messages":{"slotAvailable":{"$ref":"#/components/messages/SlotAvailable"}}
    }
  },
  "operations":{
    "subscribeProtectedWaitlist":{
      "action":"receive",
      "channel":{"$ref":"#/channels/waitlistProtected"}
    }
  },
  "components":{
    "messages":{
      "SlotAvailable":{
        "contentType":"application/json",
        "payload":{"type":"object","additionalProperties":false,"properties":{"event_type":{"type":"string","const":"slot.available"},"slot_time":{"type":"string","format":"date-time"},"doctor_id":{"type":"string"}},"required":["event_type","slot_time"]}
      }
    },
    "securitySchemes":{"aauth_subscribe":{"type":"http","scheme":"aauth-subscribe","description":"AAuth Subscribe Token as Signature-Key JWT"}}
  }
}`)
}
