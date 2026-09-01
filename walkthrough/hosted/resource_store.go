package main

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/resource"
)

type hostedR3DocumentStore struct{ store *hostedProtocolStore }
type hostedR3IssuanceStore struct{ store *hostedProtocolStore }
type hostedBudgetStore struct{ store *hostedProtocolStore }

func (documents hostedR3DocumentStore) Commit(_ context.Context, record resource.R3DocumentRecord) error {
	documents.store.mu.Lock()
	defer documents.store.mu.Unlock()
	state, err := documents.store.load()
	if err != nil {
		return err
	}
	key := record.Reference.URI()
	encoded := encodeHostedR3Document(record)
	if retained, ok := state.R3Documents[key]; ok {
		if reflect.DeepEqual(retained, encoded) {
			return nil
		}
		return resource.ErrR3DocumentConflict
	}
	state.R3Documents[key] = encoded
	return documents.store.save(state)
}

func (documents hostedR3DocumentStore) Load(_ context.Context, uri string) (resource.R3DocumentRecord, error) {
	documents.store.mu.Lock()
	defer documents.store.mu.Unlock()
	state, err := documents.store.load()
	if err != nil {
		return resource.R3DocumentRecord{}, err
	}
	encoded, ok := state.R3Documents[uri]
	if !ok {
		return resource.R3DocumentRecord{}, resource.ErrR3DocumentNotFound
	}
	return decodeHostedR3Document(encoded)
}

func (issuances hostedR3IssuanceStore) Commit(_ context.Context, record r3.IssuanceRecord) error {
	issuances.store.mu.Lock()
	defer issuances.store.mu.Unlock()
	state, err := issuances.store.load()
	if err != nil {
		return err
	}
	key := referenceKey(record.AuthTokenReference)
	encoded := encodeHostedR3Issuance(record)
	if retained, ok := state.R3Issuances[key]; ok {
		if reflect.DeepEqual(retained, encoded) {
			return nil
		}
		return r3.ErrIssuanceConflict
	}
	state.R3Issuances[key] = encoded
	return issuances.store.save(state)
}

func (budget hostedBudgetStore) Charge(_ context.Context, charge resource.BudgetCharge) (resource.BudgetChargeResult, error) {
	budget.store.mu.Lock()
	defer budget.store.mu.Unlock()
	state, err := budget.store.load()
	if err != nil {
		return resource.BudgetChargeResult{}, err
	}
	key := referenceKey(charge.Token)
	if retained, ok := state.BudgetCharges[key]; ok && !sameHostedCharge(retained, charge) {
		return resource.BudgetChargeResult{}, resource.ErrBudgetConflict
	}
	remaining := charge.Grant.Amount() - state.BudgetConsumed[key]
	if charge.Cost > remaining {
		result := resource.BudgetChargeResult{Remaining: remaining}
		if remaining == 0 {
			return result, resource.ErrBudgetExhausted
		}
		return result, resource.ErrBudgetInsufficient
	}
	state.BudgetCharges[key] = charge
	state.BudgetConsumed[key] += charge.Cost
	if err := budget.store.save(state); err != nil {
		return resource.BudgetChargeResult{}, err
	}
	return resource.BudgetChargeResult{Cost: charge.Cost, Remaining: remaining - charge.Cost}, nil
}

func (store *hostedProtocolStore) retainLineage(_ context.Context, lineage resource.BudgetLineage) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.load()
	if err != nil {
		return err
	}
	key := referenceKey(lineage.ResourceToken)
	if retained, ok := state.Lineages[key]; ok && !reflect.DeepEqual(retained, lineage) {
		return errors.New("hosted walkthrough: Budget lineage conflicts with retained state")
	}
	state.Lineages[key] = lineage
	return store.save(state)
}

func (store *hostedProtocolStore) oneLineage() (resource.BudgetLineage, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.load()
	if err != nil {
		return resource.BudgetLineage{}, err
	}
	if len(state.Lineages) != 1 {
		return resource.BudgetLineage{}, errors.New("hosted walkthrough: exact Budget lineage is unavailable")
	}
	for _, lineage := range state.Lineages {
		return lineage, nil
	}
	return resource.BudgetLineage{}, errors.New("hosted walkthrough: Budget lineage is unavailable")
}

func (store *hostedProtocolStore) connectorResult(requestKey, account, credential string) (connectorResultRecord, bool, int, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.load()
	if err != nil {
		return connectorResultRecord{}, false, 0, err
	}
	if retained, ok := state.Connector[requestKey]; ok {
		if retained.Account != account {
			return connectorResultRecord{}, false, state.ConnectorCalls, errors.New("hosted walkthrough: request key conflicts with retained account")
		}
		return retained, true, state.ConnectorCalls, nil
	}
	if credential == "" {
		return connectorResultRecord{}, false, state.ConnectorCalls, errors.New("hosted walkthrough: connector credential is unavailable")
	}
	state.ConnectorCalls++
	result := connectorResultRecord{RequestKey: requestKey, Account: account, Result: "record-" + itoa(state.ConnectorCalls)}
	state.Connector[requestKey] = result
	if err := store.save(state); err != nil {
		return connectorResultRecord{}, false, 0, err
	}
	return result, false, state.ConnectorCalls, nil
}

func (store *hostedProtocolStore) hasConnectorResult(requestKey string) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.load()
	if err != nil {
		return false, err
	}
	_, ok := state.Connector[requestKey]
	return ok, nil
}

func sameHostedCharge(left, right resource.BudgetCharge) bool {
	return left.Token == right.Token && left.PersonServer == right.PersonServer && left.Subject == right.Subject &&
		left.Audience == right.Audience && left.MissionS256 == right.MissionS256 && left.Tenant == right.Tenant &&
		sameHostedString(left.Account, right.Account) && sameHostedBudget(left.Grant, right.Grant)
}

func sameHostedString(left, right *string) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

func sameHostedBudget(left, right budgets.Value) bool {
	return left.Amount() == right.Amount() && left.Unit().Equal(right.Unit())
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	buffer := [20]byte{}
	index := len(buffer)
	for value > 0 {
		index--
		buffer[index] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[index:])
}

func encodeHostedR3Document(record resource.R3DocumentRecord) hostedR3DocumentJSON {
	owned := record.Clone()
	return hostedR3DocumentJSON{
		ReferenceURI: owned.Reference.URI(), ReferenceDigest: owned.Reference.Digest(),
		ExactJSON: owned.ExactJSON, PersonServer: owned.PersonServer,
		AuthTokenIssuer: owned.AuthTokenIssuer, AuthTokenIssuerDocument: owned.AuthTokenIssuerDocument,
		ClassContext: encodeHostedClassContext(owned.ClassContext),
	}
}

func decodeHostedR3Document(encoded hostedR3DocumentJSON) (resource.R3DocumentRecord, error) {
	reference, err := r3.NewReference(encoded.ReferenceURI, encoded.ReferenceDigest)
	if err != nil {
		return resource.R3DocumentRecord{}, err
	}
	return (resource.R3DocumentRecord{
		Reference: reference, ExactJSON: append([]byte(nil), encoded.ExactJSON...), PersonServer: encoded.PersonServer,
		AuthTokenIssuer: encoded.AuthTokenIssuer, AuthTokenIssuerDocument: encoded.AuthTokenIssuerDocument,
		ClassContext: decodeHostedClassContext(encoded.ClassContext),
	}).Clone(), nil
}

func encodeHostedClassContext(context resource.R3ClassAuthorizationContext) hostedR3ClassContextJSON {
	claims := context.ResourceToken
	additional := make(map[string]json.RawMessage, len(claims.AdditionalClaims))
	for name, value := range claims.AdditionalClaims {
		additional[name] = append(json.RawMessage(nil), value...)
	}
	var interaction *aauth.ResourceInteraction
	if claims.Interaction != nil {
		cloned := *claims.Interaction
		interaction = &cloned
	}
	return hostedR3ClassContextJSON{
		ExactResourceToken: context.ExactResourceToken,
		ResourceToken: hostedResourceTokenClaimsJSON{
			Issuer: claims.Issuer, DWK: claims.DWK, Audience: claims.Audience, JTI: claims.JTI,
			PersonServer: claims.PersonServer, Subject: claims.Subject, PresentedJTI: claims.PresentedJTI,
			AgentJKT: claims.AgentJKT, IssuedAt: claims.IssuedAt, ExpiresAt: claims.ExpiresAt,
			NotBefore: claims.NotBefore, Scope: claims.Scope, Account: cloneHostedString(claims.Account),
			MissionS256: claims.MissionS256, Tenant: claims.Tenant, Interaction: interaction,
			AdditionalClaims: additional,
		},
		PersonTokenIssuedAt: context.PersonTokenIssuedAt, PersonTokenNotBefore: context.PersonTokenNotBefore,
		PersonTokenExpiresAt: context.PersonTokenExpiresAt,
	}
}

func decodeHostedClassContext(encoded hostedR3ClassContextJSON) resource.R3ClassAuthorizationContext {
	claims := encoded.ResourceToken
	additional := make(map[string]json.RawMessage, len(claims.AdditionalClaims))
	for name, value := range claims.AdditionalClaims {
		additional[name] = append(json.RawMessage(nil), value...)
	}
	var interaction *aauth.ResourceInteraction
	if claims.Interaction != nil {
		cloned := *claims.Interaction
		interaction = &cloned
	}
	return resource.R3ClassAuthorizationContext{
		ExactResourceToken: encoded.ExactResourceToken,
		ResourceToken: aauth.ResourceTokenClaims{
			Issuer: claims.Issuer, DWK: claims.DWK, Audience: claims.Audience, JTI: claims.JTI,
			PersonServer: claims.PersonServer, Subject: claims.Subject, PresentedJTI: claims.PresentedJTI,
			AgentJKT: claims.AgentJKT, IssuedAt: claims.IssuedAt, ExpiresAt: claims.ExpiresAt,
			NotBefore: claims.NotBefore, Scope: claims.Scope, Account: cloneHostedString(claims.Account),
			MissionS256: claims.MissionS256, Tenant: claims.Tenant, Interaction: interaction,
			AdditionalClaims: additional,
		},
		PersonTokenIssuedAt: encoded.PersonTokenIssuedAt, PersonTokenNotBefore: encoded.PersonTokenNotBefore,
		PersonTokenExpiresAt: encoded.PersonTokenExpiresAt,
	}
}

func encodeHostedR3Issuance(record r3.IssuanceRecord) hostedR3IssuanceJSON {
	return hostedR3IssuanceJSON{
		AuthTokenReference: record.AuthTokenReference, Resource: record.Resource,
		ReferenceURI: record.R3Reference.URI(), ReferenceDigest: record.R3Reference.Digest(),
		Vocabulary: record.Vocabulary, IssuedAt: record.IssuedAt, PersonServer: record.PersonServer,
		Subject: record.Subject, Account: cloneHostedString(record.Account), PresentedJTI: record.PresentedJTI,
		AgentJKT: record.AgentJKT, Agent: record.Agent, ParentAgent: record.ParentAgent,
	}
}

func decodeHostedR3Issuance(encoded hostedR3IssuanceJSON) (r3.IssuanceRecord, error) {
	reference, err := r3.NewReference(encoded.ReferenceURI, encoded.ReferenceDigest)
	if err != nil {
		return r3.IssuanceRecord{}, err
	}
	return r3.IssuanceRecord{
		AuthTokenReference: encoded.AuthTokenReference, Resource: encoded.Resource, R3Reference: reference,
		Vocabulary: encoded.Vocabulary, IssuedAt: encoded.IssuedAt, PersonServer: encoded.PersonServer,
		Subject: encoded.Subject, Account: cloneHostedString(encoded.Account), PresentedJTI: encoded.PresentedJTI,
		AgentJKT: encoded.AgentJKT, Agent: encoded.Agent, ParentAgent: encoded.ParentAgent,
	}, nil
}

var _ resource.R3DocumentStore = hostedR3DocumentStore{}
var _ r3.IssuanceStore = hostedR3IssuanceStore{}
var _ resource.BudgetStore = hostedBudgetStore{}
