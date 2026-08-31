package events_test

import (
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/events"
)

func TestDeliveryFingerprintBindsTokenContentTypeAndPayload(t *testing.T) {
	t.Parallel()
	base := events.Fingerprint("event-token", "application/json", []byte(`{}`))
	for name, changed := range map[string]events.DeliveryFingerprint{
		"token":        events.Fingerprint("other-token", "application/json", []byte(`{}`)),
		"content type": events.Fingerprint("event-token", "application/cbor", []byte(`{}`)),
		"payload":      events.Fingerprint("event-token", "application/json", []byte(`[]`)),
	} {
		if changed == base {
			t.Fatalf("changing %s did not change the delivery fingerprint", name)
		}
	}
	if replay := events.Fingerprint("event-token", "application/json", []byte(`{}`)); replay != base {
		t.Fatal("exact delivery did not reproduce its fingerprint")
	}
}
