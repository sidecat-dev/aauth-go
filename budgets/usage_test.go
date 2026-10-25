package budgets

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseUsageRequestAcceptsOneScopeAndThumbprints(t *testing.T) {
	t.Parallel()
	thumbprint := base64.RawURLEncoding.EncodeToString(bytes32(7))
	request, err := ParseUsageRequest([]byte(`{"sub":"person-1","jkts":["` + thumbprint + `"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if request.Subject != "person-1" || len(request.JKTs) != 1 || request.JKTs[0] != thumbprint {
		t.Fatalf("request = %+v", request)
	}
	for _, raw := range []string{
		`{"sub":"person-1","tenant":"corp"}`,
		`{}`,
		`{"jkts":[]}`,
		`{"sub":"person-1","jkts":["not-a-thumbprint"]}`,
		`{"ps":"https://person.example"}`,
	} {
		if _, err := ParseUsageRequest([]byte(raw)); err == nil || !strings.Contains(err.Error(), "usage request") {
			t.Fatalf("request %s error = %v", raw, err)
		}
	}
}

func TestParseUsageResponseRequiresTheAnsweredCaller(t *testing.T) {
	t.Parallel()
	body := []byte(`{"as_of":1754619970,"aud":"https://person.example","unit":"USD","decimals":6,"sub":"person-1","usage":{"all_time":5}}`)
	response, err := ParseUsageResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	request := UsageRequest{Subject: "person-1"}
	if err := CheckUsageResponse(request, "https://person.example", response); err != nil {
		t.Fatal(err)
	}
	if err := CheckUsageResponse(request, "https://other.example", response); err == nil {
		t.Fatal("accepted a response addressed to someone else")
	}
	omitted := []byte(`{"as_of":1754619970,"aud":"https://person.example","unit":"USD","decimals":6,"sub":"person-1"}`)
	response, err = ParseUsageResponse(omitted)
	if err != nil || response.Usage != nil {
		t.Fatalf("omitted usage = %+v, %v", response, err)
	}
}

func bytes32(fill byte) []byte {
	raw := make([]byte, 32)
	for index := range raw {
		raw[index] = fill
	}
	return raw
}
