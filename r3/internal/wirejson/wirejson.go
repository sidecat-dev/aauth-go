// Package wirejson provides the closed, duplicate-rejecting JSON grammar
// shared by R3 vocabulary adapters. It owns no vocabulary semantics.
package wirejson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// Object decodes exactly one JSON object. Unknown and duplicate members are
// rejected before a vocabulary adapter can interpret the value.
func Object(data []byte, handlers map[string]func(json.RawMessage) error) (map[string]struct{}, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("JSON must be valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	opening, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if opening != json.Delim('{') {
		return nil, errors.New("expected a JSON object")
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		nameToken, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		name, ok := nameToken.(string)
		if !ok {
			return nil, errors.New("expected an object member name")
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, fmt.Errorf("duplicate member %q", name)
		}
		handler, known := handlers[name]
		if !known {
			return nil, fmt.Errorf("unknown member %q", name)
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, fmt.Errorf("member %q: %w", name, err)
		}
		if err := handler(raw); err != nil {
			return nil, fmt.Errorf("member %q: %w", name, err)
		}
		seen[name] = struct{}{}
	}
	closing, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if closing != json.Delim('}') {
		return nil, errors.New("invalid JSON object close")
	}
	if err := eof(decoder); err != nil {
		return nil, err
	}
	return seen, nil
}

// String decodes exactly one JSON string.
func String(raw json.RawMessage, target *string) error {
	if !utf8.Valid(raw) {
		return errors.New("JSON string must be valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return eof(decoder)
}

// StringArray decodes a JSON array containing only strings and rejects
// duplicate values.
func StringArray(raw json.RawMessage) ([]string, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("JSON array must be valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if opening != json.Delim('[') {
		return nil, errors.New("expected a JSON array")
	}
	var values []string
	seen := make(map[string]struct{})
	for decoder.More() {
		var value string
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, fmt.Errorf("duplicate value %q", value)
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	closing, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if closing != json.Delim(']') {
		return nil, errors.New("invalid JSON array close")
	}
	if err := eof(decoder); err != nil {
		return nil, err
	}
	return values, nil
}

func eof(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("unexpected trailing JSON value")
	}
	return err
}
