package exampleutil

import (
	"context"
	"errors"
	"sort"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

func (store *permissionStore) ListPendingPermissions(ctx context.Context, issuer string, at time.Time, limit int) ([]personserver.PermissionRecord, error) {
	if err := validatePendingList(ctx, limit); err != nil {
		return nil, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return pendingPermissions(store.records, issuer, at, limit), nil
}

func (store *missionStore) ListPendingPermissions(ctx context.Context, issuer string, at time.Time, limit int) ([]personserver.PermissionRecord, error) {
	if err := validatePendingList(ctx, limit); err != nil {
		return nil, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return pendingPermissions(store.permissions, issuer, at, limit), nil
}

func pendingPermissions(retained map[string]personserver.PermissionRecord, issuer string, at time.Time, limit int) []personserver.PermissionRecord {
	records := make([]personserver.PermissionRecord, 0)
	for id, record := range retained {
		if record.PersonServer != issuer {
			continue
		}
		materializePermissionExpiry(&record, at)
		retained[id] = record
		if record.State == personserver.PermissionStatePending {
			records = append(records, clonePermissionRecord(record))
		}
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].CreatedAt.Equal(records[j].CreatedAt) {
			return records[i].ID < records[j].ID
		}
		return records[i].CreatedAt.Before(records[j].CreatedAt)
	})
	if len(records) > limit {
		records = records[:limit]
	}
	return records
}

func (store *interactionQuestionStore) ListPendingInteractionQuestions(ctx context.Context, issuer string, at time.Time, limit int) ([]personserver.InteractionQuestionRecord, error) {
	if err := validatePendingList(ctx, limit); err != nil {
		return nil, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return pendingQuestions(store.records, issuer, at, limit), nil
}

func (store *missionInteractionQuestionStore) ListPendingInteractionQuestions(ctx context.Context, issuer string, at time.Time, limit int) ([]personserver.InteractionQuestionRecord, error) {
	if err := validatePendingList(ctx, limit); err != nil {
		return nil, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return pendingQuestions(store.questions, issuer, at, limit), nil
}

func pendingQuestions(retained map[string]personserver.InteractionQuestionRecord, issuer string, at time.Time, limit int) []personserver.InteractionQuestionRecord {
	records := make([]personserver.InteractionQuestionRecord, 0)
	for id, record := range retained {
		if record.PersonServer != issuer {
			continue
		}
		if record.State == personserver.InteractionQuestionPending && !at.Before(record.ExpiresAt) {
			record.State = personserver.InteractionQuestionExpired
			retained[id] = record
		}
		if record.State == personserver.InteractionQuestionPending {
			records = append(records, cloneExampleQuestionRecord(record))
		}
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].CreatedAt.Equal(records[j].CreatedAt) {
			return records[i].ID < records[j].ID
		}
		return records[i].CreatedAt.Before(records[j].CreatedAt)
	})
	if len(records) > limit {
		records = records[:limit]
	}
	return records
}

func validatePendingList(ctx context.Context, limit int) error {
	if ctx == nil {
		return errors.New("exampleutil: context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if limit < 1 || limit > 1000 {
		return errors.New("exampleutil: pending list limit must be between 1 and 1000")
	}
	return nil
}
