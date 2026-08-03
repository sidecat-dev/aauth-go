// Package jsonstrict rejects JSON object-member ambiguity before a value is
// decoded into Go structs, whose field matching is case-insensitive.
package jsonstrict

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
)

// RejectAmbiguousNames rejects exact duplicate names and case variants within
// every object. JSON names are normally case-sensitive, but admitting both
// forms before Go struct decoding would let two wire names target one field.
func RejectAmbiguousNames(value []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	if err := scanValue(decoder); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("JSON input must contain one value")
	}
	return nil
}

func scanValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return errors.New("JSON input is invalid")
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		names := make(map[string]string)
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return errors.New("JSON input is invalid")
			}
			name, ok := nameToken.(string)
			if !ok {
				return errors.New("JSON object name must be a string")
			}
			folded := foldName(name)
			if previous, duplicate := names[folded]; duplicate {
				if previous == name {
					return fmt.Errorf("JSON input contains duplicate object name %q", name)
				}
				return fmt.Errorf(
					"JSON input contains case-ambiguous object names %q and %q",
					previous,
					name,
				)
			}
			names[folded] = name
			if err := scanValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("JSON object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := scanValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("JSON array is not closed")
		}
	default:
		return errors.New("JSON input contains an invalid delimiter")
	}
	return nil
}

// foldName follows the same Unicode simple-fold equivalence used by
// encoding/json when it matches object names to Go struct fields.
func foldName(name string) string {
	var folded strings.Builder
	folded.Grow(len(name))
	for _, current := range name {
		for {
			next := unicode.SimpleFold(current)
			if next <= current {
				current = next
				break
			}
			current = next
		}
		folded.WriteRune(current)
	}
	return folded.String()
}
