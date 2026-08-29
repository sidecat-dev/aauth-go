package reference

import (
	"errors"
	"fmt"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/internal/snapshotfile"
)

func TestSnapshotFileExtractionPreservesReferenceErrorContracts(t *testing.T) {
	for _, class := range []struct {
		name                 string
		internal, event      error
		authorization, proof error
	}{
		{name: "config", internal: snapshotfile.ErrConfig, event: ErrEventStoreConfig, authorization: ErrAuthorizationStateStoreConfig, proof: ErrProofReplayStoreConfig},
		{name: "capacity", internal: snapshotfile.ErrCapacity, event: ErrEventStoreCapacity, authorization: ErrAuthorizationStateCapacity, proof: ErrProofReplayStoreCapacity},
		{name: "unsafe", internal: snapshotfile.ErrUnsafe, event: ErrEventStoreUnsafe, authorization: ErrAuthorizationStateUnsafe, proof: ErrProofReplayStoreUnsafe},
		{name: "locked", internal: snapshotfile.ErrLocked, event: ErrEventStoreLocked, authorization: ErrAuthorizationStateLocked, proof: ErrProofReplayStoreLocked},
		{name: "integrity", internal: snapshotfile.ErrIntegrity, event: ErrEventStoreIntegrity, authorization: ErrAuthorizationStateIntegrity, proof: ErrProofReplayStoreIntegrity},
		{name: "uncertain", internal: snapshotfile.ErrCommitUncertain, event: ErrEventStoreCommitUncertain, authorization: ErrAuthorizationStateUncertain, proof: ErrProofReplayStoreCommitUncertain},
		{name: "closed", internal: snapshotfile.ErrClosed, event: ErrEventStoreClosed, authorization: ErrAuthorizationStateClosed, proof: ErrProofReplayStoreClosed},
	} {
		t.Run("classified/"+class.name, func(t *testing.T) {
			event := mapEventSnapshotFileError(class.internal)
			if event != class.event {
				t.Fatalf("event error = %q, want exact %q", event, class.event)
			}
			authorization := mapAuthorizationStateFileError(class.internal)
			wantAuthorization := class.authorization.Error() + "\n" + class.event.Error()
			if authorization == nil || authorization.Error() != wantAuthorization ||
				!errors.Is(authorization, class.authorization) || !errors.Is(authorization, class.event) ||
				errors.Is(authorization, class.internal) {
				t.Fatalf("authorization error = %q, want %q with both classifications", authorization, wantAuthorization)
			}
			proof := mapProofReplayFileError(class.internal)
			wantProof := class.proof.Error() + ": " + class.event.Error()
			if proof == nil || proof.Error() != wantProof || !errors.Is(proof, class.proof) ||
				errors.Is(proof, class.event) || errors.Is(proof, class.internal) {
				t.Fatalf("proof error = %q, want %q with proof-only classification", proof, wantProof)
			}
		})
	}

	injected := errors.New("injected failure")
	for _, operation := range []struct {
		internal, reference string
	}{
		{internal: "snapshotfile: create temporary", reference: "reference: create event state temporary"},
		{internal: "snapshotfile: protect temporary", reference: "reference: protect event state temporary"},
		{internal: "snapshotfile: write state", reference: "reference: write event state"},
		{internal: "snapshotfile: sync state", reference: "reference: sync event state"},
		{internal: "snapshotfile: close state", reference: "reference: close event state"},
		{internal: "snapshotfile: publish state", reference: "reference: publish event state"},
		{internal: "snapshotfile: open directory", reference: "reference: open event state directory"},
		{internal: "snapshotfile: sync directory", reference: "reference: sync event state directory"},
		{internal: "snapshotfile: close new lock"},
		{internal: "snapshotfile: create lock"},
		{internal: "snapshotfile: inspect lock"},
		{internal: "snapshotfile: open lock"},
		{internal: "snapshotfile: inspect opened lock"},
		{internal: "snapshotfile: acquire writer lock"},
	} {
		t.Run("operation/"+operation.internal, func(t *testing.T) {
			got := mapEventSnapshotFileError(fmt.Errorf("%s: %w", operation.internal, injected))
			want := injected.Error()
			if operation.reference != "" {
				want = operation.reference + ": " + want
			}
			if got == nil || got.Error() != want || !errors.Is(got, injected) {
				t.Fatalf("mapped operation = %q, want %q retaining cause", got, want)
			}
		})
	}

	tests := []struct {
		name     string
		mapError func(error) error
		input    error
		want     string
		is       []error
		isNot    []error
	}{
		{
			name:     "event contextual custody",
			mapError: mapEventSnapshotFileError,
			input:    fmt.Errorf("%w: unexpected entry %q", snapshotfile.ErrUnsafe, "foreign"),
			want:     ErrEventStoreUnsafe.Error() + `: unexpected entry "foreign"`,
			is:       []error{ErrEventStoreUnsafe},
			isNot:    []error{snapshotfile.ErrUnsafe},
		},
		{
			name:     "event uncertain",
			mapError: mapEventSnapshotFileError,
			input:    errors.Join(snapshotfile.ErrCommitUncertain, injected),
			want:     ErrEventStoreCommitUncertain.Error() + "\n" + injected.Error(),
			is:       []error{ErrEventStoreCommitUncertain, injected},
			isNot:    []error{snapshotfile.ErrCommitUncertain},
		},
		{
			name:     "event directory sync uncertain",
			mapError: mapEventSnapshotFileError,
			input: errors.Join(
				snapshotfile.ErrCommitUncertain,
				fmt.Errorf("snapshotfile: sync directory: %w", injected),
			),
			want:  ErrEventStoreCommitUncertain.Error() + "\nreference: sync event state directory: " + injected.Error(),
			is:    []error{ErrEventStoreCommitUncertain, injected},
			isNot: []error{snapshotfile.ErrCommitUncertain},
		},
		{
			name:     "authorization uncertain",
			mapError: mapAuthorizationStateFileError,
			input:    errors.Join(snapshotfile.ErrCommitUncertain, injected),
			want: ErrAuthorizationStateUncertain.Error() + "\n" +
				ErrEventStoreCommitUncertain.Error() + "\n" + injected.Error(),
			is:    []error{ErrAuthorizationStateUncertain, ErrEventStoreCommitUncertain, injected},
			isNot: []error{snapshotfile.ErrCommitUncertain},
		},
		{
			name:     "authorization directory sync uncertain",
			mapError: mapAuthorizationStateFileError,
			input: errors.Join(
				snapshotfile.ErrCommitUncertain,
				fmt.Errorf("snapshotfile: sync directory: %w", injected),
			),
			want: ErrAuthorizationStateUncertain.Error() + "\n" +
				ErrEventStoreCommitUncertain.Error() + "\nreference: sync event state directory: " + injected.Error(),
			is:    []error{ErrAuthorizationStateUncertain, ErrEventStoreCommitUncertain, injected},
			isNot: []error{snapshotfile.ErrCommitUncertain},
		},
		{
			name:     "proof replay uncertain",
			mapError: mapProofReplayFileError,
			input:    errors.Join(snapshotfile.ErrCommitUncertain, injected),
			want: ErrProofReplayStoreCommitUncertain.Error() + ": " +
				ErrEventStoreCommitUncertain.Error() + "\n" + injected.Error(),
			is:    []error{ErrProofReplayStoreCommitUncertain},
			isNot: []error{ErrEventStoreCommitUncertain, injected},
		},
		{
			name:     "proof replay directory sync uncertain",
			mapError: mapProofReplayFileError,
			input: errors.Join(
				snapshotfile.ErrCommitUncertain,
				fmt.Errorf("snapshotfile: sync directory: %w", injected),
			),
			want: ErrProofReplayStoreCommitUncertain.Error() + ": " +
				ErrEventStoreCommitUncertain.Error() + "\nreference: sync event state directory: " + injected.Error(),
			is:    []error{ErrProofReplayStoreCommitUncertain},
			isNot: []error{ErrEventStoreCommitUncertain, snapshotfile.ErrCommitUncertain, injected},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := test.mapError(test.input)
			if got == nil || got.Error() != test.want {
				t.Fatalf("mapped error = %q, want %q", got, test.want)
			}
			for _, target := range test.is {
				if !errors.Is(got, target) {
					t.Fatalf("mapped error %q does not match %v", got, target)
				}
			}
			for _, target := range test.isNot {
				if errors.Is(got, target) {
					t.Fatalf("mapped error %q unexpectedly matches %v", got, target)
				}
			}
		})
	}
}
