package testutil_test

import (
	"context"
	"encoding/json"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/accessserver"
	accessstoretest "gitlab.com/sidecat-dev/aauth-go/accessserver/storetest"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	personstoretest "gitlab.com/sidecat-dev/aauth-go/personserver/storetest"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

func TestPublicFederationStores(t *testing.T) {
	t.Run("AS", func(t *testing.T) {
		accessstoretest.RunDeferredAuthorization(t, accessstoretest.DeferredAuthorizationContract{New: func(testing.TB) accessserver.DeferredAuthorizationStore {
			return testutil.NewAccessAuthorizationStore()
		}})
	})
	t.Run("PS", func(t *testing.T) {
		personstoretest.RunFederatedAuthorization(t, personstoretest.FederatedAuthorizationContract{New: func(testing.TB) personserver.FederatedAuthorizationStore {
			return testutil.NewFederatedAuthorizationStore()
		}})
	})
	t.Run("PS queue", func(t *testing.T) {
		personstoretest.RunFederatedAuthorizationQueue(t, personstoretest.FederatedAuthorizationQueueContract{New: func(testing.TB) personserver.FederatedAuthorizationQueueStore {
			return testutil.NewFederatedAuthorizationStore()
		}})
	})
}

// JSON-backed adapters may canonicalize timestamps to UTC while preserving
// their instants. The base contract must not mistake that for lost state.
func TestFederationContractWithJSONAndUTCTimestamps(t *testing.T) {
	personstoretest.RunFederatedAuthorization(t, personstoretest.FederatedAuthorizationContract{
		New: func(testing.TB) personserver.FederatedAuthorizationStore {
			return &jsonFederatedStore{store: testutil.NewFederatedAuthorizationStore()}
		},
	})
}

type jsonFederatedStore struct {
	store personserver.FederatedAuthorizationStore
}

func roundTripFederatedRecord(record personserver.FederatedAuthorizationRecord) (personserver.FederatedAuthorizationRecord, error) {
	data, err := json.Marshal(record)
	if err != nil {
		return personserver.FederatedAuthorizationRecord{}, err
	}
	var decoded personserver.FederatedAuthorizationRecord
	if err := json.Unmarshal(data, &decoded); err != nil {
		return decoded, err
	}
	decoded.ExpiresAt = decoded.ExpiresAt.UTC()
	decoded.NextPollAt = decoded.NextPollAt.UTC()
	return decoded, nil
}

func (s *jsonFederatedStore) CreateFederatedAuthorization(ctx context.Context, record personserver.FederatedAuthorizationRecord) error {
	record, err := roundTripFederatedRecord(record)
	if err != nil {
		return err
	}
	return s.store.CreateFederatedAuthorization(ctx, record)
}

func (s *jsonFederatedStore) LoadFederatedAuthorization(ctx context.Context, id string) (personserver.FederatedAuthorizationRecord, error) {
	record, err := s.store.LoadFederatedAuthorization(ctx, id)
	if err != nil {
		return record, err
	}
	return roundTripFederatedRecord(record)
}

func (s *jsonFederatedStore) ReplaceFederatedAuthorization(ctx context.Context, before, after personserver.FederatedAuthorizationRecord) error {
	before, err := roundTripFederatedRecord(before)
	if err != nil {
		return err
	}
	after, err = roundTripFederatedRecord(after)
	if err != nil {
		return err
	}
	return s.store.ReplaceFederatedAuthorization(ctx, before, after)
}
