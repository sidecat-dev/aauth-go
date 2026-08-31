package aauth_test

import (
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestInteractionRelayRoundTripPreservesExactRequest(t *testing.T) {
	t.Parallel()

	request := aauth.InteractionRelay{
		Type:        aauth.InteractionRelayPayment,
		Description: "Approve the **payment**.",
		URL:         "https://merchant.example/pay",
		Code:        "X7K2-M9P4",
		MaxWait:     30 * time.Second,
	}
	document, err := aauth.EncodeInteractionRelay(request)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"type":"payment","description":"Approve the **payment**.","url":"https://merchant.example/pay","code":"X7K2-M9P4","max_wait":30}`
	if string(document.ExactJSON) != want || document.Relay != request {
		t.Fatalf("relay = %#v JSON=%s", document.Relay, document.ExactJSON)
	}

	mission := aauth.MissionS256([]byte("relay mission"))
	exact := []byte("{\n  \"extension\": true,\n  \"code\": \"ABCD-EFGH\",\n  \"url\": \"https://resource.example/act\",\n  \"type\": \"interaction\",\n  \"mission_s256\": \"" + mission + "\"\n}")
	wantExact := append([]byte(nil), exact...)
	decoded, err := aauth.DecodeInteractionRelay(exact)
	if err != nil {
		t.Fatal(err)
	}
	exact[0] = '['
	if string(decoded.ExactJSON) != string(wantExact) || decoded.Relay.Type != aauth.InteractionRelayInteraction || decoded.Relay.MissionS256 != mission {
		t.Fatalf("decoded relay = %#v JSON=%s", decoded.Relay, decoded.ExactJSON)
	}
}

func TestInteractionRelayRejectsInvalidShapes(t *testing.T) {
	t.Parallel()
	for _, body := range [][]byte{
		[]byte(`[]`),
		[]byte(`{"type":"question","url":"https://r.example/a","code":"ABCD-EFGH"}`),
		[]byte(`{"type":"interaction","code":"ABCD-EFGH"}`),
		[]byte(`{"type":"interaction","url":"http://r.example/a","code":"ABCD-EFGH"}`),
		[]byte(`{"type":"interaction","url":"https://r.example/a"}`),
		[]byte(`{"type":"interaction","url":"https://r.example/a","code":"bad!"}`),
		[]byte(`{"type":"interaction","url":"https://r.example/a","code":"ABCD-EFGH","max_wait":-1}`),
		[]byte(`{"type":"interaction","url":"https://r.example/a","code":"ABCD-EFGH","question":"wrong branch"}`),
		[]byte(`{"type":"interaction","url":"https://r.example/a","code":"ABCD-EFGH","mission_s256":""}`),
		[]byte(`{"Type":"interaction","url":"https://r.example/a","code":"ABCD-EFGH"}`),
		[]byte(`{"type":"interaction","type":"payment","url":"https://r.example/a","code":"ABCD-EFGH"}`),
	} {
		if _, err := aauth.DecodeInteractionRelay(body); err == nil {
			t.Fatalf("invalid relay accepted: %s", body)
		}
	}
	for _, relay := range []aauth.InteractionRelay{
		{},
		{Type: aauth.InteractionRelayInteraction, URL: "http://r.example/a", Code: "ABCD-EFGH"},
		{Type: aauth.InteractionRelayPayment, URL: "https://r.example/a", Code: "bad!"},
		{Type: aauth.InteractionRelayPayment, URL: "https://r.example/a", Code: "ABCD-EFGH", MaxWait: 1500 * time.Millisecond},
	} {
		if _, err := aauth.EncodeInteractionRelay(relay); err == nil {
			t.Fatalf("invalid relay encoded: %#v", relay)
		}
	}
}

func TestInteractionRelayCompletionUsesOnlyCoreStatusValues(t *testing.T) {
	t.Parallel()
	for _, status := range []aauth.InteractionRelayStatus{aauth.InteractionRelayPending, aauth.InteractionRelayInteracting} {
		document, err := aauth.EncodeInteractionRelayCompletion(aauth.InteractionRelayCompletion{Status: status})
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := aauth.DecodeInteractionRelayCompletion(document.ExactJSON)
		if err != nil || decoded.Completion.Status != status {
			t.Fatalf("completion %q = %#v, %v", status, decoded, err)
		}
	}
	if _, err := aauth.DecodeInteractionRelayCompletion([]byte(`{"status":"complete"}`)); err == nil {
		t.Fatal("invented relay status accepted")
	}
}
