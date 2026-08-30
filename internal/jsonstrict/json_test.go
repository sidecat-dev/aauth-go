package jsonstrict

import "testing"

type caseFixture struct {
	Issuer string               `json:"iss"`
	Child  *caseChild           `json:"child,omitempty"`
	Items  []caseChild          `json:"items,omitempty"`
	ByID   map[string]caseChild `json:"by_id,omitempty"`
}

type caseChild struct {
	Subject string `json:"sub"`
}

func TestRejectCaseVariants(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "exact", input: `{"iss":"https://issuer.example","child":{"sub":"one"}}`},
		{name: "unknown extension", input: `{"iss":"https://issuer.example","New_Field":{"SUB":"extension-owned"}}`},
		{name: "top-level variant", input: `{"ISS":"https://issuer.example"}`, wantErr: true},
		{name: "nested pointer variant", input: `{"child":{"SUB":"one"}}`, wantErr: true},
		{name: "slice variant", input: `{"items":[{"SUB":"one"}]}`, wantErr: true},
		{name: "map value variant", input: `{"by_id":{"one":{"SUB":"one"}}}`, wantErr: true},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			err := RejectCaseVariants([]byte(test.input), &caseFixture{})
			if (err != nil) != test.wantErr {
				t.Fatalf("RejectCaseVariants() error = %v, want error %t", err, test.wantErr)
			}
		})
	}
}
