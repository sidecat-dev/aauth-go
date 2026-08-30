// Package jsonstrict rejects JSON object-member ambiguity before a value is
// decoded into Go structs, whose field matching is case-insensitive.
package jsonstrict

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode"
)

// RejectAmbiguousNames rejects exact duplicate names within every object.
// Case-distinct map keys remain distinct JSON data; RejectCaseVariants applies
// Go struct-field matching rules where a destination type is known.
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

// RejectCaseVariants rejects non-exact spellings of JSON members known to the
// destination type. Unknown members remain available to additive extensions.
func RejectCaseVariants(value []byte, destination any) error {
	if destination == nil {
		return errors.New("JSON destination is required")
	}
	if err := RejectAmbiguousNames(value); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return errors.New("JSON input is invalid")
	}
	return rejectCaseVariants(decoded, reflect.TypeOf(destination))
}

func rejectCaseVariants(value any, destination reflect.Type) error {
	for destination.Kind() == reflect.Pointer {
		destination = destination.Elem()
	}
	if value == nil {
		return nil
	}
	switch destination.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		fields := jsonFields(destination)
		for name, member := range object {
			fieldType, exact := fields[name]
			if exact {
				if err := rejectCaseVariants(member, fieldType); err != nil {
					return err
				}
				continue
			}
			folded := foldName(name)
			for canonical := range fields {
				if foldName(canonical) == folded {
					return fmt.Errorf("JSON object name %q is a case variant of %q", name, canonical)
				}
			}
		}
	case reflect.Slice, reflect.Array:
		members, ok := value.([]any)
		if !ok {
			return nil
		}
		for _, member := range members {
			if err := rejectCaseVariants(member, destination.Elem()); err != nil {
				return err
			}
		}
	case reflect.Map:
		object, ok := value.(map[string]any)
		if !ok || destination.Key().Kind() != reflect.String {
			return nil
		}
		for _, member := range object {
			if err := rejectCaseVariants(member, destination.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

func jsonFields(destination reflect.Type) map[string]reflect.Type {
	fields := make(map[string]reflect.Type)
	for index := 0; index < destination.NumField(); index++ {
		field := destination.Field(index)
		if !field.IsExported() && !field.Anonymous {
			continue
		}
		tag := field.Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if name == "-" {
			continue
		}
		if name == "" && field.Anonymous {
			embedded := field.Type
			for embedded.Kind() == reflect.Pointer {
				embedded = embedded.Elem()
			}
			if embedded.Kind() == reflect.Struct {
				for embeddedName, embeddedType := range jsonFields(embedded) {
					fields[embeddedName] = embeddedType
				}
				continue
			}
		}
		if name == "" {
			name = field.Name
		}
		fields[name] = field.Type
	}
	return fields
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
		names := make(map[string]struct{})
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return errors.New("JSON input is invalid")
			}
			name, ok := nameToken.(string)
			if !ok {
				return errors.New("JSON object name must be a string")
			}
			if _, duplicate := names[name]; duplicate {
				return fmt.Errorf("JSON input contains duplicate object name %q", name)
			}
			names[name] = struct{}{}
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
