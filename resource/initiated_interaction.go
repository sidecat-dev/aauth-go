package resource

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/interaction"
)

// MaximumInitiatedInteractionCodeAttempts is the failed-code bound for one
// Resource-initiated interaction. The interaction ends at the bound and every
// later presentation, the right code included, is refused.
const MaximumInitiatedInteractionCodeAttempts = 3

var (
	// ErrInitiatedInteractionConflict reports a duplicate identifier or a
	// store result that does not match the retained interaction.
	ErrInitiatedInteractionConflict = errors.New("resource: initiated interaction conflicts with retained state")
	// ErrInitiatedInteractionExpired reports a visit at or after the
	// interaction's deadline, which is its Resource token's expiry.
	ErrInitiatedInteractionExpired = errors.New("resource: initiated interaction expired")
	// ErrInitiatedInteractionCodeInvalid reports an unknown interaction, a
	// failed code correlation, or an interaction ended by failed attempts.
	ErrInitiatedInteractionCodeInvalid = errors.New("resource: initiated interaction code is invalid")
	// ErrInitiatedInteractionCodeUsed reports a code already consumed.
	ErrInitiatedInteractionCodeUsed = errors.New("resource: initiated interaction code was already used")
)

// InitiatedInteractionConfig enables Resource-initiated interaction (Core,
// Resource-Initiated Interaction). When Require selects it for a verified
// Person-token challenge, the Resource token carries an interaction claim
// naming {URL}/{reference} and a fresh code. The Person Server sends the
// person there with ?code={code}&callback={ps_callback_url} before its own
// consent, and the host serves that page with ConsumeInitiatedInteraction.
//
// Only Core Resource tokens issued against a Person token carry the claim:
// the authorization endpoint and the protected route's first challenge. R3
// Resource tokens never do.
type InitiatedInteractionConfig struct {
	// URL is the HTTPS base of this Resource's interaction page, without a
	// query or fragment.
	URL string
	// Require reports whether this Resource needs its own user-facing flow,
	// such as an authorization at a third-party service, before the Person
	// Server may issue. It runs after the Person token is verified.
	Require func(context.Context, InitiatedInteractionRequest) (bool, error)
	// Store retains each open interaction until its Resource token expires.
	Store InitiatedInteractionStore
}

// InitiatedInteractionRequest is the verified context Require decides on.
// Request is an independent copy of the challenged request.
type InitiatedInteractionRequest struct {
	Request *http.Request
	Person  PersonIdentity
	Context PersonContext
	Scopes  []string
}

// InitiatedInteractionRecord is the immutable context retained before a
// Resource token names an interaction. CodeSHA256 is the digest of the
// normalized code; the code itself is never retained. ExpiresAt is the
// Resource token's expiry, so the code dies with the token that carries it.
type InitiatedInteractionRecord struct {
	ID               string
	CodeSHA256       [32]byte
	Resource         string
	Person           PersonIdentity
	Tenant           string
	MissionS256      string
	Scopes           []string
	ResourceTokenJTI string
	AgentJKT         string
	CreatedAt        time.Time
	ExpiresAt        time.Time
}

// InitiatedInteractionCodePresentation is one code attempt without its
// plaintext. SyntacticallyValid is false when the presented code could not be
// normalized; such an attempt still counts as a failure.
type InitiatedInteractionCodePresentation struct {
	CodeSHA256         [32]byte
	SyntacticallyValid bool
}

// InitiatedInteractionStore retains open Resource-initiated interactions.
//
// CreateInitiatedInteraction atomically retains one record and returns
// ErrInitiatedInteractionConflict when its ID is already in use.
//
// ConsumeInitiatedInteractionCode atomically correlates one visit. It returns
// ErrInitiatedInteractionCodeInvalid for an unknown Resource and ID pair, and
// ErrInitiatedInteractionExpired at or after ExpiresAt. A presentation that is
// not SyntacticallyValid, or whose digest differs, counts as one failed
// attempt and returns ErrInitiatedInteractionCodeInvalid; after
// MaximumInitiatedInteractionCodeAttempts failures every later presentation
// returns ErrInitiatedInteractionCodeInvalid. A matching code is consumed
// once and returns an independent copy of the record; a later presentation
// returns ErrInitiatedInteractionCodeUsed.
type InitiatedInteractionStore interface {
	CreateInitiatedInteraction(context.Context, InitiatedInteractionRecord) error
	ConsumeInitiatedInteractionCode(
		ctx context.Context,
		resource string,
		reference string,
		presentation InitiatedInteractionCodePresentation,
		now time.Time,
	) (InitiatedInteractionRecord, error)
}

// InitiatedInteraction is one correlated visit to this Resource's own
// interaction page. It does not authenticate the person: the host does that
// before it runs its flow. Callback is where the party that sent the person
// asked to have them returned, whether that party is an Agent or a Person
// Server.
type InitiatedInteraction struct {
	kind     uint8
	record   InitiatedInteractionRecord
	callback string
}

const initiatedInteractionCorrelated uint8 = 1

// Reference returns the non-secret interaction reference.
func (value InitiatedInteraction) Reference() string { return value.record.ID }

// Person returns the person named by the Resource token.
func (value InitiatedInteraction) Person() PersonIdentity { return value.record.Person }

// Tenant returns the verified tenant context, if any.
func (value InitiatedInteraction) Tenant() string { return value.record.Tenant }

// MissionS256 returns the mission named by the Resource token, if any.
func (value InitiatedInteraction) MissionS256() string { return value.record.MissionS256 }

// Scopes returns an independent copy of the scopes the Resource token asks for.
func (value InitiatedInteraction) Scopes() []string {
	return append([]string(nil), value.record.Scopes...)
}

// ExpiresAt returns the interaction deadline.
func (value InitiatedInteraction) ExpiresAt() time.Time { return value.record.ExpiresAt }

// Callback returns the callback the visit carried, or empty.
func (value InitiatedInteraction) Callback() string { return value.callback }

// CompletionURL returns where to send the person when this Resource's flow
// finished: the callback. It returns an empty string when the visit carried
// no callback; the host then shows its own completion page.
func (value InitiatedInteraction) CompletionURL() (string, error) {
	return value.callbackURL("")
}

// FailureURL returns where to send the person when this Resource's flow
// cannot be completed: the callback with failure as its error parameter. It
// returns an empty string when the visit carried no callback.
func (value InitiatedInteraction) FailureURL(failure aauth.InteractionCallbackError) (string, error) {
	if !failure.Valid() {
		return "", fmt.Errorf("resource: interaction callback error %q is not registered", string(failure))
	}
	return value.callbackURL(failure)
}

func (value InitiatedInteraction) callbackURL(failure aauth.InteractionCallbackError) (string, error) {
	if value.kind != initiatedInteractionCorrelated {
		return "", errors.New("resource: correlated initiated interaction is required")
	}
	if value.callback == "" {
		return "", nil
	}
	return aauth.InteractionCallbackURL(value.callback, failure)
}

// ConsumeInitiatedInteraction correlates one visit to {URL}/{reference} and
// consumes its code. visit comes from aauth.ParseInteractionVisit; the
// Resource accepts the same query whether an Agent or a Person Server sent
// the person. After its own flow the host redirects to CompletionURL, or to
// FailureURL when the flow cannot be completed. A visit whose code does not
// correlate returns an error and no callback: the Resource does not redirect
// for an interaction it cannot identify.
func (server *Server) ConsumeInitiatedInteraction(
	ctx context.Context,
	reference string,
	visit aauth.InteractionVisit,
) (InitiatedInteraction, error) {
	if server == nil || server.initiatedInteraction == nil {
		return InitiatedInteraction{}, errors.New("resource: initiated interactions are not configured")
	}
	if ctx == nil {
		return InitiatedInteraction{}, errors.New("resource: context is required")
	}
	if reference == "" {
		return InitiatedInteraction{}, ErrInitiatedInteractionCodeInvalid
	}
	if visit.Callback != "" {
		if err := aauth.ValidateInteractionCallback(visit.Callback, true); err != nil {
			return InitiatedInteraction{}, err
		}
	}
	presentation := InitiatedInteractionCodePresentation{}
	if digest, err := interaction.Digest(visit.Code); err == nil {
		presentation.CodeSHA256 = digest
		presentation.SyntacticallyValid = true
	}
	record, err := server.initiatedInteraction.Store.ConsumeInitiatedInteractionCode(
		ctx, server.issuer, reference, presentation, server.clock.Now().UTC(),
	)
	if err != nil {
		return InitiatedInteraction{}, err
	}
	if !presentation.SyntacticallyValid || record.ID != reference || record.Resource != server.issuer ||
		record.CodeSHA256 != presentation.CodeSHA256 {
		return InitiatedInteraction{}, ErrInitiatedInteractionConflict
	}
	if err := validateInitiatedInteractionRecord(record); err != nil {
		return InitiatedInteraction{}, ErrInitiatedInteractionConflict
	}
	record.Scopes = append([]string(nil), record.Scopes...)
	return InitiatedInteraction{kind: initiatedInteractionCorrelated, record: record, callback: visit.Callback}, nil
}

func validateInitiatedInteractionConfig(config *InitiatedInteractionConfig) error {
	if config == nil {
		return nil
	}
	if config.Require == nil || config.Store == nil {
		return errors.New("aauth: initiated interaction requires a policy and a store")
	}
	if err := aauth.ValidateEndpoint(config.URL); err != nil {
		return fmt.Errorf("aauth: initiated interaction URL: %w", err)
	}
	return nil
}

// openInitiatedInteraction asks host policy whether this challenge needs the
// Resource's own flow and, when it does, retains the interaction and puts the
// claim in claims before the Resource token is minted.
func (server *Server) openInitiatedInteraction(
	request *http.Request,
	person aauth.PersonTokenClaims,
	scopes []string,
	claims *aauth.ResourceTokenClaims,
) error {
	config := server.initiatedInteraction
	if config == nil {
		return nil
	}
	policyRequest, finish, err := cloneScopePolicyRequest(request)
	if err != nil {
		return err
	}
	required, err := config.Require(policyRequest.Context(), InitiatedInteractionRequest{
		Request: policyRequest,
		Person:  PersonIdentity{Issuer: person.Issuer, Subject: person.Subject},
		Context: PersonContext{MissionS256: person.MissionS256, Tenant: person.Tenant},
		Scopes:  append([]string(nil), scopes...),
	})
	if finishErr := finish(); err == nil && finishErr != nil {
		err = finishErr
	}
	if err != nil || !required {
		return err
	}
	createdAt := time.Unix(claims.IssuedAt, 0).UTC()
	for attempt := 0; attempt < 3; attempt++ {
		reference, err := interaction.GeneratePendingReference(nil)
		if err != nil {
			return fmt.Errorf("resource: generate interaction reference: %w", err)
		}
		code, err := interaction.GenerateCode(nil)
		if err != nil {
			return fmt.Errorf("resource: generate interaction code: %w", err)
		}
		digest, err := interaction.Digest(code)
		if err != nil {
			return err
		}
		interactionURL, err := appendSessionInteractionReference(config.URL, reference)
		if err != nil {
			return err
		}
		record := InitiatedInteractionRecord{
			ID: reference, CodeSHA256: digest, Resource: server.issuer,
			Person: PersonIdentity{Issuer: claims.PersonServer, Subject: claims.Subject},
			Tenant: claims.Tenant, MissionS256: claims.MissionS256,
			Scopes:           append([]string(nil), scopes...),
			ResourceTokenJTI: claims.JTI, AgentJKT: claims.AgentJKT,
			CreatedAt: createdAt, ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(),
		}
		if err := validateInitiatedInteractionRecord(record); err != nil {
			return err
		}
		if err := config.Store.CreateInitiatedInteraction(request.Context(), record); err != nil {
			if errors.Is(err, ErrInitiatedInteractionConflict) {
				continue
			}
			return err
		}
		claims.Interaction = &aauth.ResourceInteraction{URL: interactionURL, Code: code}
		return nil
	}
	return errors.New("resource: could not allocate a unique initiated interaction")
}

func validateInitiatedInteractionRecord(record InitiatedInteractionRecord) error {
	if record.ID == "" || record.CodeSHA256 == ([32]byte{}) || record.Resource == "" ||
		record.ResourceTokenJTI == "" || record.AgentJKT == "" ||
		record.CreatedAt.IsZero() || !record.ExpiresAt.After(record.CreatedAt) {
		return errors.New("resource: initiated interaction record is invalid")
	}
	if err := aauth.ValidateServerIdentifier(record.Person.Issuer); err != nil || record.Person.Subject == "" {
		return errors.New("resource: initiated interaction person is invalid")
	}
	if slices.Contains(record.Scopes, "") {
		return errors.New("resource: initiated interaction scope is invalid")
	}
	return nil
}
