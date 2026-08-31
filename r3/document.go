package r3

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Display describes human-readable consequences of granting a document's
// operations.
type Display struct {
	summary      string
	implications string
	dataAccessed string
	irreversible string
}

// NewDisplay constructs a validated display value. The final three arguments
// are optional strings and may be empty.
func NewDisplay(summary, implications, dataAccessed, irreversible string) (Display, error) {
	display := Display{
		summary:      summary,
		implications: implications,
		dataAccessed: dataAccessed,
		irreversible: irreversible,
	}
	if err := display.validate(); err != nil {
		return Display{}, err
	}
	return display, nil
}

func (d Display) validate() error {
	if !utf8.ValidString(d.summary) {
		return fmt.Errorf("r3: display summary must be valid UTF-8")
	}
	if !utf8.ValidString(d.implications) {
		return fmt.Errorf("r3: display implications must be valid UTF-8")
	}
	if !utf8.ValidString(d.dataAccessed) {
		return fmt.Errorf("r3: display data_accessed must be valid UTF-8")
	}
	if !utf8.ValidString(d.irreversible) {
		return fmt.Errorf("r3: display irreversible must be valid UTF-8")
	}
	if strings.TrimSpace(d.summary) == "" {
		return fmt.Errorf("r3: display summary is required")
	}
	return nil
}

// Summary returns the required consent-screen summary.
func (d Display) Summary() string { return d.summary }

// Implications returns the optional side-effect description.
func (d Display) Implications() string { return d.implications }

// DataAccessed returns the optional accessed-data description.
func (d Display) DataAccessed() string { return d.dataAccessed }

// Irreversible returns the optional irreversible-action description.
func (d Display) Irreversible() string { return d.irreversible }

// MarshalJSON emits only the defined display members.
func (d Display) MarshalJSON() ([]byte, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Summary      string `json:"summary"`
		Implications string `json:"implications,omitempty"`
		DataAccessed string `json:"data_accessed,omitempty"`
		Irreversible string `json:"irreversible,omitempty"`
	}{
		Summary:      d.summary,
		Implications: d.implications,
		DataAccessed: d.dataAccessed,
		Irreversible: d.irreversible,
	})
}

// UnmarshalJSON accepts only the exact R3 display shape.
func (d *Display) UnmarshalJSON(data []byte) error {
	display, err := parseDisplay(data)
	if err != nil {
		return err
	}
	*d = display
	return nil
}

func parseDisplay(data []byte) (Display, error) {
	var summary, implications, dataAccessed, irreversible string
	seen, err := decodeStrictObject(data, map[string]func(json.RawMessage) error{
		"summary": func(raw json.RawMessage) error {
			return decodeJSONString(raw, &summary)
		},
		"implications": func(raw json.RawMessage) error {
			return decodeJSONString(raw, &implications)
		},
		"data_accessed": func(raw json.RawMessage) error {
			return decodeJSONString(raw, &dataAccessed)
		},
		"irreversible": func(raw json.RawMessage) error {
			return decodeJSONString(raw, &irreversible)
		},
	})
	if err != nil {
		return Display{}, fmt.Errorf("r3: invalid display: %w", err)
	}
	if _, ok := seen["summary"]; !ok {
		return Display{}, fmt.Errorf("r3: display is missing summary")
	}
	return NewDisplay(summary, implications, dataAccessed, irreversible)
}

// DocumentOptions supplies the two optional R3 document fields. NewDocument
// copies the values referenced here.
type DocumentOptions struct {
	Account *string
	Display *Display
}

// Document is a validated vocabulary-neutral R3 document value. It does not
// retain the source JSON bytes used to parse it.
type Document struct {
	operationSet OperationSet
	account      *string
	display      *Display
}

// NewDocument constructs a validated R3 document.
func NewDocument(operationSet OperationSet, options DocumentOptions) (Document, error) {
	if err := operationSet.value.validate(); err != nil {
		return Document{}, fmt.Errorf("r3: invalid document operation set: %w", err)
	}
	document := Document{operationSet: OperationSet{value: operationSet.value.clone()}}
	if options.Account != nil {
		if !utf8.ValidString(*options.Account) {
			return Document{}, fmt.Errorf("r3: document account must be valid UTF-8")
		}
		account := *options.Account
		document.account = &account
	}
	if options.Display != nil {
		if err := options.Display.validate(); err != nil {
			return Document{}, err
		}
		display := *options.Display
		document.display = &display
	}
	return document, nil
}

// OperationSet returns a copy of the document's exact operation set.
func (d Document) OperationSet() OperationSet {
	return OperationSet{value: d.operationSet.value.clone()}
}

// Account returns the account and whether the optional member was present.
func (d Document) Account() (string, bool) {
	if d.account == nil {
		return "", false
	}
	return *d.account, true
}

// Display returns the display value and whether the optional member was
// present.
func (d Document) Display() (Display, bool) {
	if d.display == nil {
		return Display{}, false
	}
	return *d.display, true
}

// MarshalJSON serializes operation-set fields at the document's top level.
func (d Document) MarshalJSON() ([]byte, error) {
	if err := d.operationSet.value.validate(); err != nil {
		return nil, fmt.Errorf("r3: invalid document operation set: %w", err)
	}
	if d.display != nil {
		if err := d.display.validate(); err != nil {
			return nil, err
		}
	}
	return json.Marshal(struct {
		Vocabulary VocabularyURI     `json:"vocabulary"`
		Operations []json.RawMessage `json:"operations"`
		Account    *string           `json:"account,omitempty"`
		Display    *Display          `json:"display,omitempty"`
	}{
		Vocabulary: d.operationSet.Vocabulary(),
		Operations: cloneRawMessages(d.operationSet.value.raw),
		Account:    d.account,
		Display:    d.display,
	})
}

// UnmarshalJSON rejects context-free parsing because the vocabulary must be
// selected from an explicit allowlisted Registry.
func (*Document) UnmarshalJSON([]byte) error {
	return fmt.Errorf("r3: Document requires a vocabulary registry; use Registry.ParseDocument")
}

// ParseDocument parses a validated document without retaining source bytes.
func (registry Registry) ParseDocument(source []byte) (Document, error) {
	var vocabulary string
	var operationsRaw json.RawMessage
	var account string
	var display Display
	seen, err := decodeStrictObject(source, map[string]func(json.RawMessage) error{
		"vocabulary": func(raw json.RawMessage) error {
			return decodeJSONString(raw, &vocabulary)
		},
		"operations": func(raw json.RawMessage) error {
			operationsRaw = append(operationsRaw[:0], raw...)
			return nil
		},
		"account": func(raw json.RawMessage) error {
			return decodeJSONString(raw, &account)
		},
		"display": func(raw json.RawMessage) error {
			parsed, err := parseDisplay(raw)
			if err != nil {
				return err
			}
			display = parsed
			return nil
		},
	})
	if err != nil {
		return Document{}, fmt.Errorf("r3: invalid document: %w", err)
	}
	if _, ok := seen["vocabulary"]; !ok {
		return Document{}, fmt.Errorf("r3: document is missing vocabulary")
	}
	if _, ok := seen["operations"]; !ok {
		return Document{}, fmt.Errorf("r3: document is missing operations")
	}
	uri := VocabularyURI(vocabulary)
	registered, ok := registry.vocabularies[uri]
	if !ok {
		return Document{}, fmt.Errorf("r3: vocabulary %q is not registered", uri)
	}
	operations, err := decodeJSONArray(operationsRaw)
	if err != nil {
		return Document{}, err
	}
	operationSet, err := newParsedOperationSet(registered, operations, setUseDocument)
	if err != nil {
		return Document{}, err
	}
	options := DocumentOptions{}
	if _, ok := seen["account"]; ok {
		options.Account = &account
	}
	if _, ok := seen["display"]; ok {
		options.Display = &display
	}
	return NewDocument(operationSet, options)
}

// ParseReferencedDocument binds exact bytes to reference before parsing.
func (registry Registry) ParseReferencedDocument(reference Reference, exactBytes []byte) (Document, error) {
	if err := reference.validate(); err != nil {
		return Document{}, fmt.Errorf("r3: invalid reference: %w", err)
	}
	if Digest(exactBytes) != reference.digest {
		return Document{}, fmt.Errorf("r3: referenced document digest mismatch")
	}
	return registry.ParseDocument(exactBytes)
}

// Digest returns unpadded base64url SHA-256 over the exact caller-supplied
// bytes. It performs no parsing, canonicalization, or reserialization.
func Digest(source []byte) string {
	sum := sha256.Sum256(source)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func decodeStrictObject(data []byte, allowed map[string]func(json.RawMessage) error) (map[string]struct{}, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	opening, ok := token.(json.Delim)
	if !ok || opening != '{' {
		return nil, fmt.Errorf("expected JSON object")
	}

	seen := make(map[string]struct{}, len(allowed))
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		name, ok := token.(string)
		if !ok {
			return nil, fmt.Errorf("expected object member name")
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, fmt.Errorf("duplicate member %q", name)
		}
		handler, known := allowed[name]
		if !known {
			return nil, fmt.Errorf("unknown member %q", name)
		}
		seen[name] = struct{}{}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, fmt.Errorf("member %q: %w", name, err)
		}
		if err := handler(raw); err != nil {
			return nil, fmt.Errorf("member %q: %w", name, err)
		}
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, err
	}
	return seen, nil
}

func decodeJSONArray(data []byte) ([]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, fmt.Errorf("expected JSON array")
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	var values []json.RawMessage
	if err := decoder.Decode(&values); err != nil {
		return nil, err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, err
	}
	return values, nil
}

func decodeJSONString(data []byte, destination *string) error {
	trimmed := bytes.TrimSpace(data)
	if !utf8.Valid(trimmed) {
		return fmt.Errorf("expected valid UTF-8 JSON string")
	}
	if len(trimmed) == 0 || trimmed[0] != '"' {
		return fmt.Errorf("expected JSON string")
	}
	return json.Unmarshal(trimmed, destination)
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if err == io.EOF {
		return nil
	}
	if err == nil {
		return fmt.Errorf("unexpected trailing JSON value")
	}
	return err
}
