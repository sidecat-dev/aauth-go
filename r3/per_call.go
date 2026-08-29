package r3

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime"
	"reflect"

	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
)

// PerCallProposal is invalid-zero, copy-safe evidence for one exact R3
// proposal document. A proposal names exactly one operation and carries a
// parameters object, including an empty object when the call has no
// parameters.
type PerCallProposal struct {
	exact      []byte
	document   Document
	digestKeys map[string]struct{}
	seal       [sha256.Size]byte
}

// PresentedParameter is one call-time value. PresentedJSON is used for an
// inline proposal value; PresentedBytes is used when the proposal contains an
// s256 digest object.
type PresentedParameter struct {
	kind  presentedParameterKind
	value []byte
}

type presentedParameterKind uint8

const (
	presentedParameterJSON presentedParameterKind = iota + 1
	presentedParameterBytes
)

// PresentedParameters is the exact named parameter set reconstructed from the
// call the resource is about to execute.
type PresentedParameters map[string]PresentedParameter

// PresentedJSON makes a defensive copy of one inline JSON parameter.
func PresentedJSON(value json.RawMessage) PresentedParameter {
	return PresentedParameter{kind: presentedParameterJSON, value: append([]byte(nil), value...)}
}

// PresentedBytes makes a defensive copy of one byte value named by an s256
// proposal parameter.
func PresentedBytes(value []byte) PresentedParameter {
	return PresentedParameter{kind: presentedParameterBytes, value: append([]byte(nil), value...)}
}

// ParsePerCallProposal validates the exact proposal serialization without
// replacing it with re-marshaled bytes.
func ParsePerCallProposal(exact []byte) (PerCallProposal, error) {
	document, err := ParseDocument(exact)
	if err != nil {
		return PerCallProposal{}, err
	}
	if len(document.Operations) != 1 {
		return PerCallProposal{}, errors.New("aauth: R3 per-call proposal requires exactly one operation")
	}
	if document.Parameters == nil {
		return PerCallProposal{}, errors.New("aauth: R3 per-call proposal requires a parameters object")
	}
	digestKeys := make(map[string]struct{})
	for name, raw := range document.Parameters {
		if name == "" {
			return PerCallProposal{}, errors.New("aauth: R3 per-call proposal parameter name is empty")
		}
		digest, recognized, parseErr := parseDigestParameter(raw)
		if parseErr != nil {
			return PerCallProposal{}, fmt.Errorf("aauth: R3 per-call proposal parameter %q: %w", name, parseErr)
		}
		if recognized {
			if err := digest.validate(); err != nil {
				return PerCallProposal{}, fmt.Errorf("aauth: R3 per-call proposal parameter %q: %w", name, err)
			}
			digestKeys[name] = struct{}{}
		}
	}
	proposal := PerCallProposal{
		exact: append([]byte(nil), exact...), document: cloneDocument(document),
		digestKeys: digestKeys,
	}
	proposal.seal = proposal.sealValue()
	return proposal, nil
}

// Valid reports whether the proposal still identifies its exact validated
// serialization.
func (proposal PerCallProposal) Valid() bool {
	return proposal.seal != [sha256.Size]byte{} && proposal.seal == proposal.sealValue()
}

// ExactBytes returns an independent copy of the proposal serialization.
func (proposal PerCallProposal) ExactBytes() []byte {
	if !proposal.Valid() {
		return nil
	}
	return append([]byte(nil), proposal.exact...)
}

// Operation returns the proposal's single operation as an independent set.
func (proposal PerCallProposal) Operation() (OperationSet, error) {
	if !proposal.Valid() {
		return OperationSet{}, errors.New("aauth: R3 per-call proposal is invalid")
	}
	return proposal.document.OperationSet(), nil
}

// Match verifies that the call supplies exactly the approved parameter names
// and forms. Inline JSON uses structural value equality. Digest parameters use
// SHA-256 over the exact presented bytes.
func (proposal PerCallProposal) Match(presented PresentedParameters) error {
	if !proposal.Valid() {
		return errors.New("aauth: R3 per-call proposal is invalid")
	}
	if len(presented) != len(proposal.document.Parameters) {
		return errors.New("aauth: R3 per-call parameters differ from the proposal")
	}
	for name, approved := range proposal.document.Parameters {
		actual, present := presented[name]
		if !present {
			return fmt.Errorf("aauth: R3 per-call parameter %q is missing", name)
		}
		if _, digest := proposal.digestKeys[name]; digest {
			if actual.kind != presentedParameterBytes {
				return fmt.Errorf("aauth: R3 per-call parameter %q must be presented as exact bytes", name)
			}
			want, _, err := parseDigestParameter(approved)
			if err != nil || want.S256 != S256(actual.value) {
				return fmt.Errorf("aauth: R3 per-call parameter %q digest does not match", name)
			}
			continue
		}
		if actual.kind != presentedParameterJSON {
			return fmt.Errorf("aauth: R3 per-call parameter %q must be presented as JSON", name)
		}
		equal, err := equalJSONValues(approved, actual.value)
		if err != nil {
			return fmt.Errorf("aauth: R3 per-call parameter %q: %w", name, err)
		}
		if !equal {
			return fmt.Errorf("aauth: R3 per-call parameter %q does not match", name)
		}
	}
	return nil
}

type digestParameter struct {
	S256      string `json:"s256"`
	Excerpt   string `json:"excerpt,omitempty"`
	MediaType string `json:"media_type,omitempty"`
}

func parseDigestParameter(raw json.RawMessage) (digestParameter, bool, error) {
	if len(raw) == 0 || raw[0] != '{' {
		return digestParameter{}, false, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return digestParameter{}, false, nil
	}
	if _, present := fields["s256"]; !present {
		return digestParameter{}, false, nil
	}
	if err := jsonstrict.RejectAmbiguousNames(raw); err != nil {
		return digestParameter{}, true, err
	}
	var parameter digestParameter
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&parameter); err != nil {
		return digestParameter{}, true, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return digestParameter{}, true, errors.New("digest object must contain one JSON value")
	}
	return parameter, true, nil
}

func (parameter digestParameter) validate() error {
	digest, err := base64.RawURLEncoding.DecodeString(parameter.S256)
	if err != nil || len(digest) != sha256.Size {
		return errors.New("s256 must be an unpadded base64url SHA-256 digest")
	}
	if parameter.MediaType != "" {
		if parsed, _, err := mime.ParseMediaType(parameter.MediaType); err != nil || parsed == "" {
			return errors.New("media_type must be a valid media type")
		}
	}
	return nil
}

func equalJSONValues(left, right []byte) (bool, error) {
	decode := func(exact []byte) (any, error) {
		if err := jsonstrict.RejectAmbiguousNames(exact); err != nil {
			return nil, err
		}
		decoder := json.NewDecoder(bytes.NewReader(exact))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			return nil, errors.New("presented value is not valid JSON")
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return nil, errors.New("presented value must contain one JSON value")
		}
		return value, nil
	}
	want, err := decode(left)
	if err != nil {
		return false, err
	}
	got, err := decode(right)
	if err != nil {
		return false, err
	}
	return equalDecodedJSON(want, got), nil
}

func equalDecodedJSON(left, right any) bool {
	switch left := left.(type) {
	case json.Number:
		right, ok := right.(json.Number)
		if !ok {
			return false
		}
		leftNumber, leftOK := new(big.Rat).SetString(string(left))
		rightNumber, rightOK := new(big.Rat).SetString(string(right))
		return leftOK && rightOK && leftNumber.Cmp(rightNumber) == 0
	case []any:
		right, ok := right.([]any)
		if !ok || len(left) != len(right) {
			return false
		}
		for index := range left {
			if !equalDecodedJSON(left[index], right[index]) {
				return false
			}
		}
		return true
	case map[string]any:
		right, ok := right.(map[string]any)
		if !ok || len(left) != len(right) {
			return false
		}
		for name, value := range left {
			other, present := right[name]
			if !present || !equalDecodedJSON(value, other) {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(left, right)
	}
}

func (proposal PerCallProposal) sealValue() [sha256.Size]byte {
	if len(proposal.exact) == 0 || len(proposal.document.Operations) != 1 || proposal.document.Parameters == nil {
		return [sha256.Size]byte{}
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte("gitlab.com/sidecat-dev/aauth-go/r3-per-call-proposal/v1\x00"))
	_, _ = digest.Write(proposal.exact)
	var seal [sha256.Size]byte
	copy(seal[:], digest.Sum(nil))
	return seal
}
