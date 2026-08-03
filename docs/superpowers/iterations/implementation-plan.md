# AAuth Events Public Subscription Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers-sidecat:subagent-driven-development (recommended) or
> superpowers-sidecat:executing-plans to implement this plan task-by-task.
> Sidecat work items, gates, logs, and evidence carry active progress; this
> repository artifact records the accepted implementation contract only.

**Goal:** Implement the accepted M5 public, payload-free, single-use Events
journey from AP subscription issuance through one independently verified agent
action with honest restart and unknown-consequence handling.

**Architecture:** Portable token and `self-jwt` verification remain in the root
`aauth` package. The `reference` package composes that protocol into AP,
resource, adapter, and agent host services behind deployment-owned authority
interfaces. Bounded single-writer file adapters qualify recovery and
replacement; they are not an enterprise or federation storage model.

**Tech Stack:** Go 1.24, `net/http`, Ed25519 JWS and HTTP Message Signatures,
strict JSON decoding, injected clocks/resolvers/stores/actions, and the existing
real-HTTP logical gateway test harness.

## Global Constraints

- Keep the module standalone: no Sidecat imports, types, stores, policy, or
  configuration.
- Add the externally visible real-HTTP failing behavior before production code.
- M5 is public registration, payload-free delivery, and `max_uses: 1` only.
- Protected tickets, AsyncAPI, payloads, and multi-event replay remain M6.
- `sig=self-jwt` uses one discovered key for the JWT and HTTP signature.
- Subscribe tokens require `dwk=aauth-agent.json`; event tokens require
  `dwk=aauth-resource.json` at both AP and agent verification.
- Resource subscription identity is `(AP issuer, eid)`; agent action identity
  is `(resource issuer, AP issuer, eid)`.
- AP `202` follows one atomic use-and-inbox commit. An exact retry after a lost
  response returns exhausted `429` without a second use or inbox record.
- Agent processing distinguishes `pending`, `dispatched`, `completed`, and
  `refused`; outcome-unknown work is never acknowledged as terminal.
- Run focused tests at every RED/GREEN cycle and the full test, race, vet,
  build, source-coverage, validator, and whitespace corpus before completion.

---

### Task 1: Lock the complete real-HTTP journey in RED

**Files:**

- Create: `events_journey_test.go`
- Modify: `docs/superpowers/iterations/behavior-corpus.md`

**Interfaces:**

- Consumes: existing `newLogicalGateway`, `testSigningKey`, mutable test clock,
  and real reference handlers.
- Produces: `TestPublicSubscriptionEventSurvivesHostReconstruction`, the stable
  M5 sentinel command, and test helpers that reconstruct each host from only
  durable interface state.

- [ ] **Step 1: Write the failing journey test**

```go
func TestPublicSubscriptionEventSurvivesHostReconstruction(t *testing.T) {
	journey := newPublicEventsJourney(t)
	subscribeToken := journey.issueOneUseSubscription()
	journey.registerPublicSubscription(subscribeToken)
	journey.expireRegistrationTokenAndRotateAPEndpoint()
	journey.sendOnePayloadFreeEventWithLostFirstResponse()
	journey.reconstructAPResourceAdapterAndAgent()
	journey.retryExactEventAndCompleteAgentAction()

	if got := journey.acceptedInboxCount(); got != 1 {
		t.Fatalf("accepted inbox records = %d, want 1", got)
	}
	if got := journey.completedActionCount(); got != 1 {
		t.Fatalf("completed actions = %d, want 1", got)
	}
	journey.assertNoPayloadAtAnyBoundary()
}
```

- [ ] **Step 2: Run the journey and record the intentional RED**

Run: `go test ./... -run '^TestPublicSubscriptionEventSurvivesHostReconstruction$' -count=1`

Expected: FAIL at compile time because the accepted Events host interfaces and
services do not exist; no production code has changed.

- [ ] **Step 3: Record the exact sentinel in the corpus**

```markdown
`go test ./... -run '^TestPublicSubscriptionEventSurvivesHostReconstruction$' -count=1`
```

- [ ] **Step 4: Record RED evidence**

Use the active Sidecat M5 work item to retain the failing invocation and exact
compiler output before Task 2 begins.

### Task 2: Add portable Events tokens and generic self-jwt proof

**Files:**

- Create: `events.go`
- Create: `events_test.go`
- Create: `http_signature_self_jwt_test.go`
- Modify: `http_signature.go`
- Modify: `token.go`

**Interfaces:**

- Consumes: `SigningKey`, `KeyResolver`, `Clock`, strict compact-JWS helpers,
  `signRequestWithSignatureKey`, and the existing typed signature errors.
- Produces:

```go
const SubscribeTokenType = "aa-subscribe+jwt"
const EventTokenType = "aa-event+jwt"
const SignatureKeySelfJWT = "self-jwt"

type SubscribeTokenClaims struct {
	Issuer string; DWK string; Subject string; Audience string
	Confirmation Confirmation; EventID string; IssuedAt int64
	ExpiresAt int64; MaxUses *int
}
type EventTokenClaims struct {
	Issuer string; DWK string; Audience string; EventID string
	IssuedAt int64; ExpiresAt int64
}
type VerifiedSelfJWT struct {
	Header TokenHeader
	Issuer string
	DWK string
	Claims json.RawMessage
}

func MintSubscribeToken(SigningKey, SubscribeTokenClaims) (string, error)
func VerifySubscribeToken(context.Context, string, KeyResolver, Clock) (SubscribeTokenClaims, error)
func MintEventToken(SigningKey, EventTokenClaims) (string, error)
func DecodeVerifiedEventToken(VerifiedSelfJWT, Clock) (EventTokenClaims, error)
func SignRequestWithSelfJWT(*http.Request, SigningKey, string, Clock) error
```

- [ ] **Step 1: Write focused token and self-jwt failures**

```go
func TestSelfJWTRejectsUnsafeClaimsBeforeDiscovery(t *testing.T) {}
func TestSelfJWTUsesOneDiscoveredKeyForBothProofs(t *testing.T) {}
func TestSubscribeAndEventClaimsRejectRequiredFieldMutations(t *testing.T) {}
```

The mutation tables cover wrong/absent `typ`, exact `dwk`, `sub`, `iat`,
`exp`, `aud`, `eid`, `cnf`, `kid`, and `alg=none`. The generic token decoder
preserves absent or positive non-one `max_uses`; the reference host mutation
matrix rejects those policies in Tasks 4 and 5.

- [ ] **Step 2: Verify the focused RED**

Run: `go test . -run '^(TestSelfJWT|TestSubscribeAndEvent)' -count=1`

Expected: FAIL because `self-jwt` and Events token APIs are absent.

- [ ] **Step 3: Implement generic structural preflight and dual proof**

Add `SignatureKeySelfJWT` parsing with only `jwt`; before resolver access reject
malformed JWT, unexpected type, expired `exp`, missing/unsafe `iss` or `dwk`,
missing `kid`, or any `cnf`. Resolve once, verify the JWS, retain strict raw
claims in `VerifiedSelfJWT`, and reuse the same JWK for the HTTP signature.

- [ ] **Step 4: Implement strict Events claim codecs**

Subscribe verification validates the agent identifier, exact discovery
document, non-future `iat`, future `exp`, resource audience, confirmation key,
non-empty `eid`, and optional positive `max_uses`. Event decoding validates
exact resource discovery, required NumericDate `iat`, future `exp`, agent
audience, non-empty `eid`, and absence of `cnf` or event data.

- [ ] **Step 5: Run focused and sentinel tests**

Run: `go test . -run '^(TestSelfJWT|TestSubscribeAndEvent)' -count=1`

Expected: PASS.

Run: `go test ./... -count=1`

Expected: existing M3/M4 tests PASS; the complete M5 journey remains RED only
at the first unimplemented reference-host API.

- [ ] **Step 6: Record the core-proof checkpoint through Sidecat**

Retain the focused GREEN invocation and reviewed patch under the M5 work item.

### Task 3: Define replaceable event authorities and memory qualification stores

**Files:**

- Create: `reference/events.go`
- Create: `reference/events_store_test.go`

**Interfaces:**

- Consumes: root Events claims, `Clock`, and `context.Context`.
- Produces:

```go
type APEventSubscription struct {
	APIssuer string
	EventID string
	Resource string
	Agent string
	ActiveUntil time.Time
	MaxUses int
	UseCount int
}
type AcceptedEventInput struct {
	Resource string
	Agent string
	EventID string
	Token string
	AcceptedAt time.Time
}
type AcceptedEvent struct {
	Delivery EventDeliveryKey
	APIssuer string
	Token string
	AcceptedAt time.Time
}
type ResourceEventSubscription struct {
	APIssuer string
	EventID string
	Resource string
	Agent string
	ActiveUntil time.Time
}
type PendingEventDelivery struct {
	APIssuer string
	EventID string
	Token string
	CreatedAt time.Time
}
type AgentEventContext struct {
	APIssuer string
	EventID string
	Value json.RawMessage
}
type EventActionKey struct {
	ResourceIssuer string
	APIssuer string
	EventID string
}
type EventProcessingState string
const (
	EventPending EventProcessingState = "pending"
	EventDispatched EventProcessingState = "dispatched"
	EventCompleted EventProcessingState = "completed"
	EventRefused EventProcessingState = "refused"
)
type EventRefusalReason string
const (
	EventRefusalInvalid EventRefusalReason = "invalid"
	EventRefusalExpired EventRefusalReason = "expired"
	EventRefusalUnknownContext EventRefusalReason = "unknown_context"
	EventRefusalNotApplied EventRefusalReason = "not_applied"
)
type AgentEventProcessing struct {
	Delivery EventDeliveryKey
	Action EventActionKey
	State EventProcessingState
	ExpiresAt time.Time
}
type APEventStore interface {
	CreateSubscription(context.Context, APEventSubscription) error
	AcceptEvent(context.Context, AcceptedEventInput) (AcceptedEvent, int, error)
	NextDelivery(context.Context) (AcceptedEvent, error)
	AcknowledgeDelivery(context.Context, string) error
}
type ResourceEventStore interface {
	Register(context.Context, ResourceEventSubscription) error
	Load(context.Context, string, string) (ResourceEventSubscription, error)
	RetainPending(context.Context, PendingEventDelivery) error
	CompletePending(context.Context, string, string) error
}
type AgentEventStore interface {
	PutContext(context.Context, AgentEventContext) error
	LookupContext(context.Context, string, string) (AgentEventContext, error)
	AdmitProcessing(context.Context, AgentEventProcessing) error
	MarkDispatched(context.Context, EventActionKey) error
	MarkCompleted(context.Context, EventActionKey) error
	MarkRefused(context.Context, EventDeliveryKey, EventRefusalReason) error
	LoadProcessing(context.Context, EventActionKey) (AgentEventProcessing, error)
	LoadDisposition(context.Context, EventDeliveryKey) (EventProcessingState, error)
}
type EventDeliveryKey struct {
	APIssuer string
	DeliveryID string
	TokenDigest string
}
type EventActionInput struct {
	Key EventActionKey
	Context AgentEventContext
	Event EventTokenClaims
}
type EventActionOutcome string
const (
	EventActionCompleted EventActionOutcome = "completed"
	EventActionNotApplied EventActionOutcome = "not_applied"
	EventActionUnknown EventActionOutcome = "unknown"
)
type EventAction interface {
	Dispatch(context.Context, EventActionInput) (EventActionOutcome, error)
	Reconcile(context.Context, EventActionKey) (EventActionOutcome, error)
}
```

Memory stores implement the same interfaces used by file adapters.

- [ ] **Step 1: Write transaction and federation tests**

```go
func TestMemoryAPEventStoreCommitsUseAndInboxAtomically(t *testing.T) {}
func TestMemoryResourceEventStoreKeysSubscriptionsByAPIssuerAndEID(t *testing.T) {}
func TestMemoryAgentEventStorePreservesUnknownDispatch(t *testing.T) {}
```

- [ ] **Step 2: Verify RED**

Run: `go test ./reference -run '^TestMemory.*EventStore' -count=1`

Expected: FAIL because the authority interfaces and stores are absent.

- [ ] **Step 3: Implement typed records, errors, and locked memory stores**

The AP accept method performs one lock-protected use check, increment, delivery
identifier allocation, and exact-token inbox insert. Resource keys are
`(AP issuer,eid)`. Agent processing keys are
`(resource issuer,AP issuer,eid)`, while untrusted refusals use trusted
`(AP issuer,delivery id)` plus exact-token digest.

- [ ] **Step 4: Run focused and race tests**

Run: `go test -race ./reference -run '^TestMemory.*EventStore' -count=1`

Expected: PASS, including one winner for concurrent final-use acceptance.

### Task 4: Issue subscriptions and advertise the AP endpoint

**Files:**

- Create: `reference/events_provider_test.go`
- Modify: `reference/provider.go`

**Interfaces:**

- Consumes: `APEventStore`, `MintSubscribeToken`, provider signing key and
  identifier source.
- Produces:

```go
type AgentProviderEventsConfig struct {
	EventEndpoint string
	Store APEventStore
	SubscriptionActiveUntil func(context.Context, string, string) (time.Time, error)
	TokenLifetime time.Duration
}
type EventSubscriptionRequest struct {
	Resource string
	Agent string
	AgentKey JWK
}
func (p *AgentProvider) IssueEventSubscription(context.Context, EventSubscriptionRequest) (string, error)
```

- [ ] **Step 1: Write collision, commit-failure, restart, and metadata tests**

```go
func TestAgentProviderIssuesOnlyAfterDurableSubscriptionCommit(t *testing.T) {}
func TestAgentProviderEventsMetadataRotatesWithHTTPFreshness(t *testing.T) {}
```

- [ ] **Step 2: Verify RED**

Run: `go test ./reference -run '^TestAgentProvider.*Event' -count=1`

Expected: FAIL because provider Events configuration is absent.

- [ ] **Step 3: Implement issuance and metadata projection**

Validate HTTPS endpoint, exact resource and agent identifiers, `max_uses: 1`,
and independent AP `active_until`; collision or store failure releases no
token. Add `event_endpoint` only when Events is configured.

- [ ] **Step 4: Run focused tests**

Run: `go test ./reference -run '^TestAgentProvider.*Event' -count=1`

Expected: PASS.

### Task 5: Register public subscriptions with durable agent and resource custody

**Files:**

- Create: `reference/events_registration_test.go`
- Modify: `reference/agent.go`
- Modify: `reference/resource.go`

**Interfaces:**

- Consumes: `AgentEventStore`, `ResourceEventStore`, `VerifySubscribeToken`,
  existing real HTTP client and key resolver.
- Produces:

```go
type AgentEventsConfig struct { Store AgentEventStore; Action EventAction }
type ResourceEventsConfig struct {
	PublicSubscriptionPath string
	Store ResourceEventStore
	ActiveUntil func(context.Context, SubscribeTokenClaims) (time.Time, error)
}
func (a *Agent) RegisterPublicEventSubscription(context.Context, string, string, AgentEventContext) error
```

- [ ] **Step 1: Write the real endpoint and mutation matrix RED**

```go
func TestPublicEventRegistrationRequiresExactSubscribeTokenAndAgentProof(t *testing.T) {}
func TestPublicEventRegistrationCustodySurvivesReconstruction(t *testing.T) {}
```

- [ ] **Step 2: Verify RED**

Run: `go test ./reference -run '^TestPublicEventRegistration' -count=1`

Expected: FAIL at the missing Agent/Resource Events configuration.

- [ ] **Step 3: Implement context-before-send and resource commit-before-success**

The agent stores `(AP issuer,eid)` context before signing with only the
subscribe token. The resource verifies exact Events claims and matching
`cnf.jwk` request proof, requires host-selected `max_uses: 1`, commits
independent `active_until`, and collision-refuses `(AP issuer,eid)`.

- [ ] **Step 4: Run focused and journey tests**

Run: `go test ./reference -run '^TestPublicEventRegistration' -count=1`

Expected: PASS.

Run: `go test ./... -run '^TestPublicSubscriptionEventSurvivesHostReconstruction$' -count=1`

Expected: RED at event delivery, after registration has succeeded.

### Task 6: Resolve, retain, send, and atomically accept one event

**Files:**

- Create: `discovery_events_test.go`
- Create: `reference/events_delivery_test.go`
- Modify: `discovery.go`
- Modify: `reference/provider.go`
- Modify: `reference/resource.go`

**Interfaces:**

- Consumes: admitted HTTP discovery, `ResourceEventStore`, `APEventStore`,
  self-jwt signing/verification, and current reference handlers.
- Produces:

```go
type AgentEventMetadata struct { Issuer string; EventEndpoint string }
func (r *HTTPKeyResolver) ResolveAgentEventMetadata(context.Context, string) (AgentEventMetadata, error)
func (r *Resource) DeliverEvent(context.Context, string, string) error
```

- [ ] **Step 1: Write endpoint-rotation, lost-response, and refusal REDs**

```go
func TestAgentEventMetadataUsesAdmittedHTTPFreshness(t *testing.T) {}
func TestEventDeliveryRetainsExactJWTAndReconcilesLost202With429(t *testing.T) {}
func TestAPEventEndpointCommitsInboxBefore202(t *testing.T) {}
```

- [ ] **Step 2: Verify RED**

Run: `go test ./... -run '^(TestAgentEventMetadata|TestEventDelivery|TestAPEventEndpoint)' -count=1`

Expected: FAIL because delivery-time metadata and handlers are absent.

- [ ] **Step 3: Implement admitted cached metadata and resource pending custody**

Resolve `event_endpoint` at delivery time under standard HTTP freshness. Mint
one exact payload-free event JWT, retain it before the first bodyless POST, and
retry only that JWT with a fresh HTTP signature after an unknown response.

- [ ] **Step 4: Implement the AP validation and atomic acceptance handler**

Apply generic self-jwt verification, then Events `dwk`, `iat`, `exp`, resource,
agent, active subscription, and one-use policy. Return the draft's
`400/401/403/404/429` classes. Return `202 {"remaining_uses":0}` only after
atomic inbox/use commit; exact or different post-exhaustion JWTs return `429`.

- [ ] **Step 5: Run focused, concurrency, and journey tests**

Run: `go test -race ./... -run '^(TestAgentEventMetadata|TestEventDelivery|TestAPEventEndpoint)' -count=1`

Expected: PASS.

Run: `go test ./... -run '^TestPublicSubscriptionEventSurvivesHostReconstruction$' -count=1`

Expected: RED only at adapter/agent continuation.

### Task 7: Continue through honest agent processing and reconciliation

**Files:**

- Create: `reference/events_agent_test.go`
- Modify: `reference/events.go`
- Modify: `reference/agent.go`

**Interfaces:**

- Consumes: AP inbox records, `AgentEventStore`, `EventAction`, event claim
  decoder, key resolver, and clock.
- Produces:

```go
type EventAdapter struct {
	source APEventStore
	agent *Agent
}
func NewEventAdapter(APEventStore, *Agent) (*EventAdapter, error)
func (a *EventAdapter) Continue(context.Context) error
func (a *Agent) AcceptEvent(context.Context, AcceptedEvent) (EventProcessingState, error)
func (a *Agent) ResumeEvents(context.Context) error
```

- [ ] **Step 1: Write crash-state and independent-verification REDs**

```go
func TestAgentEventProcessingReconcilesDispatchedUnknownHonestly(t *testing.T) {}
func TestAgentEventProcessingPersistsTerminalRefusalWithoutAction(t *testing.T) {}
func TestEventAdapterAcknowledgesOnlyDurableTerminalDisposition(t *testing.T) {}
```

- [ ] **Step 2: Verify RED**

Run: `go test ./reference -run '^(TestAgentEventProcessing|TestEventAdapter)' -count=1`

Expected: FAIL because adapter and processing services are absent.

- [ ] **Step 3: Implement independent verification and durable states**

Invalid token/context deliveries become terminal refused by trusted delivery
identity without trusting claims. Valid work becomes pending, rechecks expiry,
then transitions to dispatched before action. Reconcile dispatched work as
completed, proven not-applied, or unknown; unknown remains unacknowledged.

- [ ] **Step 4: Run focused and full journey tests**

Run: `go test -race ./reference -run '^(TestAgentEventProcessing|TestEventAdapter)' -count=1`

Expected: PASS.

Run: `go test ./... -run '^TestPublicSubscriptionEventSurvivesHostReconstruction$' -count=1`

Expected: PASS for the first time.

- [ ] **Step 5: Record the walking-skeleton GREEN checkpoint through Sidecat**

Retain the exact passing journey invocation and reviewed patch before storage
qualification begins.

### Task 8: Qualify bounded crash-safe file adapters

**Files:**

- Create: `reference/events_file_store.go`
- Create: `reference/events_file_lock_unix.go`
- Create: `reference/events_file_store_test.go`

**Interfaces:**

- Consumes: the host store interfaces and typed records from Task 3.
- Produces: `FileAPEventStore`, `FileResourceEventStore`, and
  `FileAgentEventStore`, each configured with `MaxRecords`, `MaxBytes`, and
  `MaxRecordBytes`, each owning an exclusive advisory writer lock until
  `Close`.

- [ ] **Step 1: Write capacity, custody, corruption, and crash REDs**

```go
func TestFileEventStoresEnforceEveryConfiguredLimit(t *testing.T) {}
func TestFileEventStoresRefuseUnsafeCustodyAndConcurrentWriter(t *testing.T) {}
func TestFileEventStoresPreserveCommittedSnapshotAcrossPartialWrite(t *testing.T) {}
func TestFileEventStoresRefuseCorruptTruncatedAndUnknownVersions(t *testing.T) {}
```

- [ ] **Step 2: Verify RED**

Run: `go test ./reference -run '^TestFileEventStores' -count=1`

Expected: FAIL because file adapters are absent.

- [ ] **Step 3: Implement one shared bounded file engine behind distinct adapters**

Require `0700` directories and `0600` regular files; refuse symlinks,
unexpected entries, unsafe modes, and a second writer. Encode explicit schema
versions. Check record and byte limits before mutation. Commit via private temp
file, file sync, atomic rename, and directory sync; injected failure reports no
success and never exposes partial successor state.

- [ ] **Step 4: Run focused tests with race detection**

Run: `go test -race ./reference -run '^TestFileEventStores' -count=1`

Expected: PASS, including reopen after process-object reconstruction.

- [ ] **Step 5: Run the full journey once with memory and once with file stores**

Run: `go test ./... -run '^TestPublicSubscriptionEventSurvivesHostReconstruction$' -count=1`

Expected: both subtests PASS without protocol or service API changes.

### Task 9: Close evidence and claims without widening M5

**Files:**

- Modify: `README.md`
- Modify: `SOURCE-COVERAGE.md`
- Modify: `internal/sourcecoverage/source-coverage.json`
- Modify: `docs/superpowers/iterations/behavior-corpus.md`
- Modify: `docs/superpowers/iterations/behavior-scenarios.md`
- Modify: `docs/superpowers/iterations/coverage-ledger.md`
- Modify: `docs/superpowers/iterations/iteration-log.md`
- Modify: `docs/superpowers/iterations/requirements/EPIC-002.md`
- Modify: `docs/superpowers/iterations/requirements/EPIC-003.md`
- Modify: `docs/superpowers/iterations/roadmap.md`

**Interfaces:**

- Consumes: all executable M5 evidence.
- Produces: exact commands for JOURNEY-0002 and SCENARIO-0009 through
  SCENARIO-0024, honest source coverage, and a completed ITER-0003 record.

- [ ] **Step 1: Record exact test selectors for every scenario**

Every scenario row names its real test command and owning stories; no row is
marked automated until that exact command passes.

- [ ] **Step 2: Update public claims and source coverage**

State that M5 supports one public payload-free single-shot event. State that
protected tickets, AsyncAPI, payloads, multi-event replay, standardized
AP-to-agent transport, and enterprise/distributed reference storage remain
unsupported.

- [ ] **Step 3: Run the complete verification corpus**

Run:

```text
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
go build ./...
go run ./cmd/aauth-reference verify coverage --source-dir /home/jgay-automate/workspaces/aauth-dev-workspace --repo .
python3 /home/jgay-automate/.codex/skills/extracting-requirements/scripts/validate_requirements_index.py docs/superpowers/iterations/requirements/
python3 /home/jgay-automate/.codex/skills/extracting-requirements/scripts/validate_scenarios.py docs/superpowers/iterations/behavior-scenarios.md docs/superpowers/iterations/requirements/
python3 /home/jgay-automate/.codex/skills/scoping-the-simplest-core/scripts/check_citations.py docs/superpowers/iterations/roadmap.md docs/superpowers/iterations/requirements/
python3 /home/jgay-automate/.codex/skills/scoping-the-simplest-core/scripts/validate_roadmap.py docs/superpowers/iterations/roadmap.md
git diff --check
```

Expected: every command exits zero; source coverage reports `status: verified`.

- [ ] **Step 4: Run the three-tier progress audit**

Deep-audit JOURNEY-0002 and the recovery/store scenarios, run all impacted M5
scenarios, then run the complete M3/M4 sentinel corpus. Reopen any story whose
evidence does not independently prove its acceptance criteria.

- [ ] **Step 5: Commit, integrate, and publish only through governed Git operations**

Use the active Sidecat session, selected M5 repository, exact index tree,
reviewed commit, exact branch ref, and remote-parity observation. Do not add a
co-author trailer and do not close the work item before build and test evidence
is attached.
