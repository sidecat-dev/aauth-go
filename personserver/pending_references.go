package personserver

import (
	"context"
	"errors"
	"time"
)

// PermissionQueueStore optionally exposes retained pending permission requests
// to the Person Server host. Existing PermissionStore adapters need not implement
// this interface unless the host uses PendingPermissionReferences.
//
// ListPendingPermissions returns at most limit records belonging to personServer,
// ordered by CreatedAt then ID. It atomically materializes expiry at now and
// excludes every non-pending record. Records and their mutable fields are
// independent copies. limit must be between 1 and 1000; a canceled context or
// invalid limit returns an error. Listing neither claims work nor decides it.
// Mission state is checked separately when the host resumes or decides a request.
type PermissionQueueStore interface {
	PermissionStore
	ListPendingPermissions(ctx context.Context, personServer string, now time.Time, limit int) ([]PermissionRecord, error)
}

// InteractionQuestionQueueStore optionally exposes retained pending questions
// to the Person Server host. ListPendingInteractionQuestions follows the same
// ordering, issuer isolation, bounds, expiry and copy rules as PermissionQueueStore.
// Listing does not answer a question or reserve it for one reviewer.
type InteractionQuestionQueueStore interface {
	InteractionQuestionStore
	ListPendingInteractionQuestions(ctx context.Context, personServer string, now time.Time, limit int) ([]InteractionQuestionRecord, error)
}

// PendingPermissionReferences lists a bounded snapshot of retained pending
// permission references. The configured store must implement PermissionQueueStore.
// The host must authenticate the person separately and call ResumePermission
// before presenting or deciding a request. State may change after listing;
// references confer no authority and do not imply that a mission remains active.
func (server *Server) PendingPermissionReferences(ctx context.Context, limit int) ([]string, error) {
	if err := validatePendingList(ctx, limit); err != nil {
		return nil, err
	}
	if server == nil {
		return nil, errors.New("personserver: permission queue is not configured")
	}
	queue, ok := server.permissions.(PermissionQueueStore)
	if !ok {
		return nil, errors.New("personserver: permission store does not support pending listing")
	}
	now := server.clock.Now().UTC()
	records, err := queue.ListPendingPermissions(ctx, server.issuer, now, limit)
	if err != nil {
		return nil, err
	}
	if len(records) > limit {
		return nil, ErrPermissionConflict
	}
	refs := make([]string, 0, len(records))
	seen := make(map[string]bool, len(records))
	for _, record := range records {
		if validatePermissionRecordAt(record, now) != nil || record.PersonServer != server.issuer || record.State != PermissionStatePending || seen[record.ID] {
			return nil, ErrPermissionConflict
		}
		seen[record.ID] = true
		refs = append(refs, record.ID)
	}
	return refs, nil
}

// PendingInteractionQuestionReferences lists a bounded snapshot of retained
// pending question references. The store must implement InteractionQuestionQueueStore.
// The host authenticates the person separately and calls ResumeInteractionQuestion
// before displaying or answering a question. References are not authority;
// expiry, a concurrent answer or mission termination can make them unusable.
func (server *Server) PendingInteractionQuestionReferences(ctx context.Context, limit int) ([]string, error) {
	if err := validatePendingList(ctx, limit); err != nil {
		return nil, err
	}
	if server == nil {
		return nil, errors.New("personserver: interaction question queue is not configured")
	}
	queue, ok := server.interactionQuestionStore.(InteractionQuestionQueueStore)
	if !ok {
		return nil, errors.New("personserver: interaction question store does not support pending listing")
	}
	now := server.clock.Now().UTC()
	records, err := queue.ListPendingInteractionQuestions(ctx, server.issuer, now, limit)
	if err != nil {
		return nil, err
	}
	if len(records) > limit {
		return nil, ErrInteractionQuestionConflict
	}
	refs := make([]string, 0, len(records))
	seen := make(map[string]bool, len(records))
	for _, record := range records {
		if validateInteractionQuestionRecordAt(record, now) != nil || record.PersonServer != server.issuer || record.State != InteractionQuestionPending || seen[record.ID] {
			return nil, ErrInteractionQuestionConflict
		}
		seen[record.ID] = true
		refs = append(refs, record.ID)
	}
	return refs, nil
}

func validatePendingList(ctx context.Context, limit int) error {
	if ctx == nil {
		return errors.New("personserver: context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if limit < 1 || limit > 1000 {
		return errors.New("personserver: pending list limit must be between 1 and 1000")
	}
	return nil
}
