package events_test

import (
	"strings"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/events"
)

// draftAsyncAPIDocument is the Events Example AsyncAPI Document in JSON.
const draftAsyncAPIDocument = `{
  "asyncapi": "3.0.0",
  "info": {"title": "Appointments Events", "version": "1.0.0"},
  "channels": {
    "waitlistPublic": {
      "address": "/appointments/waitlist/public",
      "messages": {"slotAvailable": {"$ref": "#/components/messages/SlotAvailable"}}
    },
    "waitlistProtected": {
      "address": "/appointments/waitlist/{subscriptionTicket}",
      "parameters": {"subscriptionTicket": {"description": "Single-use ticket from the POST /appointments response."}},
      "messages": {"slotAvailable": {"$ref": "#/components/messages/SlotAvailable"}}
    }
  },
  "operations": {
    "subscribePublicWaitlist": {
      "action": "receive",
      "channel": {"$ref": "#/channels/waitlistPublic"},
      "security": [{"$ref": "#/components/securitySchemes/aauth_subscribe"}]
    },
    "subscribeProtectedWaitlist": {
      "action": "receive",
      "channel": {"$ref": "#/channels/waitlistProtected"}
    }
  },
  "components": {
    "messages": {
      "SlotAvailable": {
        "contentType": "application/json",
        "payload": {
          "type": "object",
          "properties": {
            "event_type": {"type": "string", "const": "slot.available"},
            "slot_time": {"type": "string", "format": "date-time"},
            "doctor_id": {"type": "string"}
          },
          "required": ["event_type", "slot_time"]
        }
      }
    },
    "securitySchemes": {
      "aauth_subscribe": {
        "type": "http",
        "scheme": "aauth-subscribe",
        "description": "AAuth Subscribe Token as Signature-Key JWT"
      }
    }
  }
}`

func TestValidateAsyncAPIDocumentRequiresTheSubscribeSecurityScheme(t *testing.T) {
	t.Parallel()

	if err := events.ValidateAsyncAPIDocument([]byte(draftAsyncAPIDocument)); err != nil {
		t.Fatalf("draft example document = %v", err)
	}
	scheme := `"aauth_subscribe": {
        "type": "http",
        "scheme": "aauth-subscribe",
        "description": "AAuth Subscribe Token as Signature-Key JWT"
      }`
	if !strings.Contains(draftAsyncAPIDocument, scheme) {
		t.Fatal("test fixture no longer contains the scheme declaration")
	}
	tests := map[string]string{
		"no scheme":            strings.Replace(draftAsyncAPIDocument, scheme, `"other": {"type": "http", "scheme": "bearer"}`, 1),
		"another name":         strings.Replace(draftAsyncAPIDocument, `"aauth_subscribe": {`, `"aauthSubscribe": {`, 1),
		"wrong type":           strings.Replace(draftAsyncAPIDocument, `"type": "http",`, `"type": "httpApiKey",`, 1),
		"wrong scheme":         strings.Replace(draftAsyncAPIDocument, `"scheme": "aauth-subscribe"`, `"scheme": "bearer"`, 1),
		"missing scheme":       strings.Replace(draftAsyncAPIDocument, `"scheme": "aauth-subscribe",`, ``, 1),
		"case-variant member":  strings.Replace(draftAsyncAPIDocument, `"type": "http",`, `"Type": "http",`, 1),
		"duplicate member":     strings.Replace(draftAsyncAPIDocument, `"type": "http",`, `"type": "http", "type": "oauth2",`, 1),
		"reference":            strings.Replace(draftAsyncAPIDocument, scheme, `"aauth_subscribe": {"$ref": "#/components/securitySchemes/other"}`, 1),
		"no components":        `{"asyncapi": "3.0.0", "info": {"title": "x", "version": "1"}}`,
		"no asyncapi version":  strings.Replace(draftAsyncAPIDocument, `"asyncapi": "3.0.0",`, ``, 1),
		"trailing value":       draftAsyncAPIDocument + ` {}`,
		"not a JSON object":    `["asyncapi"]`,
		"YAML instead of JSON": "asyncapi: 3.0.0\ncomponents:\n  securitySchemes:\n    aauth_subscribe:\n      type: http\n      scheme: aauth-subscribe\n",
	}
	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := events.ValidateAsyncAPIDocument([]byte(document)); err == nil {
				t.Fatalf("ValidateAsyncAPIDocument accepted %s", name)
			}
		})
	}
}
