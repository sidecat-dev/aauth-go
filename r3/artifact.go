package r3

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ArtifactKind distinguishes a class authorization document from a concrete
// per-call proposal. It is protocol state, not vocabulary dispatch.
type ArtifactKind uint8

const (
	ArtifactDocument ArtifactKind = iota + 1
	ArtifactProposal
)

// ReferencedArtifact binds one validated reference to the exact bytes and the
// closed R3 artifact parsed from those bytes.
type ReferencedArtifact struct {
	kind      ArtifactKind
	reference Reference
	exact     []byte
	document  Document
	proposal  Proposal
}

// ParseReferencedArtifact verifies exact-byte identity before selecting the
// named vocabulary or parsing any operation.
func (registry Registry) ParseReferencedArtifact(reference Reference, exact []byte) (ReferencedArtifact, error) {
	if err := reference.validate(); err != nil {
		return ReferencedArtifact{}, fmt.Errorf("r3: invalid artifact reference: %w", err)
	}
	if Digest(exact) != reference.digest {
		return ReferencedArtifact{}, errors.New("r3: referenced artifact digest mismatch")
	}

	var parametersPresent bool
	_, err := decodeStrictObject(exact, map[string]func(json.RawMessage) error{
		"vocabulary": func(json.RawMessage) error { return nil },
		"operations": func(json.RawMessage) error { return nil },
		"parameters": func(json.RawMessage) error { parametersPresent = true; return nil },
		"account":    func(json.RawMessage) error { return nil },
		"display":    func(json.RawMessage) error { return nil },
	})
	if err != nil {
		return ReferencedArtifact{}, fmt.Errorf("r3: invalid artifact envelope: %w", err)
	}

	artifact := ReferencedArtifact{reference: reference, exact: append([]byte(nil), exact...)}
	if parametersPresent {
		proposal, err := registry.ParseProposal(exact)
		if err != nil {
			return ReferencedArtifact{}, err
		}
		artifact.kind = ArtifactProposal
		artifact.proposal = proposal
		return artifact, nil
	}
	document, err := registry.ParseDocument(exact)
	if err != nil {
		return ReferencedArtifact{}, err
	}
	artifact.kind = ArtifactDocument
	artifact.document = document
	return artifact, nil
}

// Kind returns the closed artifact classification.
func (artifact ReferencedArtifact) Kind() ArtifactKind { return artifact.kind }

// Reference returns the exact validated reference.
func (artifact ReferencedArtifact) Reference() Reference { return artifact.reference }

// ExactBytes returns an owned copy of the bytes used for identity and parsing.
func (artifact ReferencedArtifact) ExactBytes() []byte { return append([]byte(nil), artifact.exact...) }

// Document returns the class document, when this is one.
func (artifact ReferencedArtifact) Document() (Document, bool) {
	if artifact.kind != ArtifactDocument {
		return Document{}, false
	}
	return artifact.document, true
}

// Proposal returns the per-call proposal, when this is one.
func (artifact ReferencedArtifact) Proposal() (Proposal, bool) {
	if artifact.kind != ArtifactProposal {
		return Proposal{}, false
	}
	return artifact.proposal, true
}
