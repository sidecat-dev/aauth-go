package graphql

import (
	"errors"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/r3"
)

func TestIntrospectionDefinitionRefusesUnavailableOperationIdentity(t *testing.T) {
	source := NewIntrospectionSource([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"}}}}`))
	_, err := ParseDefinition("https://resource.example/graphql", source)
	var refusal *r3.DefinitionError
	if !errors.As(err, &refusal) {
		t.Fatalf("error = %T %v", err, err)
	}
	if refusal.Kind != r3.DefinitionIdentityUnavailable || refusal.Vocabulary != URI {
		t.Fatalf("refusal = %#v", refusal)
	}
}

func TestIntrospectionDefinitionSeparatesInvalidAndIncompleteSources(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  string
		kind r3.DefinitionErrorKind
	}{
		{name: "invalid JSON", raw: `{`, kind: r3.DefinitionInvalidSource},
		{name: "missing data", raw: `{"errors":[]}`, kind: r3.DefinitionIncompleteSource},
		{name: "missing schema", raw: `{"data":{}}`, kind: r3.DefinitionIncompleteSource},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseDefinition(
				"https://resource.example/graphql",
				NewIntrospectionSource([]byte(test.raw)),
			)
			var refusal *r3.DefinitionError
			if !errors.As(err, &refusal) || refusal.Kind != test.kind {
				t.Fatalf("refusal = %T %v", err, err)
			}
		})
	}
}

func TestIntrospectionSourceOwnsExactBytes(t *testing.T) {
	exact := []byte(`{"data":{"__schema":{}}}`)
	source := NewIntrospectionSource(exact)
	exact[0] = '['
	if got := string(source.ExactBytes()); got != `{"data":{"__schema":{}}}` {
		t.Fatalf("exact bytes = %s", got)
	}
	copy := source.ExactBytes()
	copy[0] = '['
	if got := string(source.ExactBytes()); got != `{"data":{"__schema":{}}}` {
		t.Fatalf("source changed through returned bytes: %s", got)
	}
}

func TestGraphQLDefinitionRegistrationIsStable(t *testing.T) {
	registry, err := r3.NewDefinitionRegistry(DefinitionRegistration())
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Validate(r3.AuthoritativeSnapshot{}); err == nil {
		t.Fatal("registry accepted an uninitialized snapshot")
	}
}
