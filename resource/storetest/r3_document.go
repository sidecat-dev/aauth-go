package storetest

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/resource"
)

// R3DocumentContract constructs a fresh empty R3 document store.
type R3DocumentContract struct {
	New func(testing.TB) resource.R3DocumentStore
}

// RunR3Document checks immutable URI binding, independent input and output
// ownership, not-found behavior, conflict refusal, and concurrent exact replay.
func RunR3Document(t *testing.T, contract R3DocumentContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("storetest: R3DocumentContract.New is required")
	}
	store := contract.New(t)
	ctx := context.Background()
	record := r3DocumentRecord(t, "https://resource.example/r3/document-1")
	pristine := record.Clone()

	if _, err := store.Load(ctx, record.Reference.URI()); !errors.Is(err, resource.ErrR3DocumentNotFound) {
		t.Fatalf("initial Load = %v", err)
	}
	if err := store.Commit(ctx, record); err != nil {
		t.Fatalf("first Commit = %v", err)
	}
	record.ExactJSON[0] = '['
	*record.ClassContext.ResourceToken.Account = "mutated-account"
	record.ClassContext.ResourceToken.Interaction.Code = "mutated-code"
	record.ClassContext.ResourceToken.AdditionalClaims["r3"] = json.RawMessage(`{"mutated":true}`)

	loaded, err := store.Load(ctx, pristine.Reference.URI())
	if err != nil || !reflect.DeepEqual(loaded, pristine) {
		t.Fatalf("Load after input mutation = %#v, %v", loaded, err)
	}
	loaded.ExactJSON[0] = '['
	*loaded.ClassContext.ResourceToken.Account = "mutated-output"
	loadedAgain, err := store.Load(ctx, pristine.Reference.URI())
	if err != nil || !reflect.DeepEqual(loadedAgain, pristine) {
		t.Fatalf("second Load after output mutation = %#v, %v", loadedAgain, err)
	}

	var wait sync.WaitGroup
	errorsByCall := make([]error, 16)
	for index := range errorsByCall {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			errorsByCall[index] = store.Commit(ctx, pristine)
		}(index)
	}
	wait.Wait()
	for index, err := range errorsByCall {
		if err != nil {
			t.Fatalf("concurrent exact Commit %d = %v", index, err)
		}
	}

	conflicting := pristine.Clone()
	conflicting.PersonServer = "https://other-person.example"
	if err := store.Commit(ctx, conflicting); !errors.Is(err, resource.ErrR3DocumentConflict) {
		t.Fatalf("conflicting Commit = %v", err)
	}
	loadedAgain, err = store.Load(ctx, pristine.Reference.URI())
	if err != nil || !reflect.DeepEqual(loadedAgain, pristine) {
		t.Fatalf("Load after conflict = %#v, %v", loadedAgain, err)
	}
}

func r3DocumentRecord(t *testing.T, uri string) resource.R3DocumentRecord {
	t.Helper()
	reference, err := r3.NewReference(uri, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	account := "account-1"
	return resource.R3DocumentRecord{
		Reference:               reference,
		ExactJSON:               []byte(`{"tools":[{"name":"read"}]}`),
		PersonServer:            "https://person.example",
		AuthTokenIssuer:         "https://person.example",
		AuthTokenIssuerDocument: "aauth-person.json",
		ClassContext: resource.R3ClassAuthorizationContext{
			ExactResourceToken: "resource-token",
			ResourceToken: aauth.ResourceTokenClaims{
				Issuer: "https://resource.example", JTI: "resource-token-1",
				Account:          &account,
				Interaction:      &aauth.ResourceInteraction{URL: "https://resource.example/interact", Code: "code-1"},
				AdditionalClaims: map[string]json.RawMessage{"r3": json.RawMessage(`{"uri":"document-1"}`)},
			},
			PersonTokenIssuedAt: 1, PersonTokenNotBefore: 2, PersonTokenExpiresAt: 3,
		},
	}
}
