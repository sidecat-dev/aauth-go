package budgets

import (
	"errors"
	"fmt"

	"github.com/dunglas/httpsfv"
)

// Header is the understood projection of one AAuth-Budget response field.
// Unknown dictionary members are deliberately ignored.
type Header struct {
	Remaining int64
	Cost      *int64
	Reserved  *int64
	Required  *int64
	Unit      string
	Decimals  *int64
}

// OptionalInteger returns an independent optional Structured Field integer.
func OptionalInteger(value int64) *int64 { return &value }

// FormatHeader serializes one current AAuth-Budget dictionary.
func FormatHeader(header Header) (string, error) {
	if err := validateHeader(header); err != nil {
		return "", err
	}
	dictionary := httpsfv.NewDictionary()
	dictionary.Add("remaining", httpsfv.NewItem(header.Remaining))
	for _, member := range []struct {
		name  string
		value *int64
	}{{"cost", header.Cost}, {"reserved", header.Reserved}, {"required", header.Required}} {
		if member.value != nil {
			dictionary.Add(member.name, httpsfv.NewItem(*member.value))
		}
	}
	if header.Unit != "" {
		dictionary.Add("unit", httpsfv.NewItem(header.Unit))
		dictionary.Add("decimals", httpsfv.NewItem(*header.Decimals))
	}
	exact, err := httpsfv.Marshal(dictionary)
	if err != nil {
		return "", fmt.Errorf("aauth budgets: format AAuth-Budget: %w", err)
	}
	return exact, nil
}

// ParseHeader parses one or more combined AAuth-Budget field lines.
func ParseHeader(values []string) (Header, error) {
	dictionary, err := httpsfv.UnmarshalDictionary(values)
	if err != nil {
		return Header{}, fmt.Errorf("aauth budgets: parse AAuth-Budget: %w", err)
	}
	var header Header
	remaining, present := dictionary.Get("remaining")
	if !present {
		return Header{}, errors.New("aauth budgets: AAuth-Budget requires remaining")
	}
	remainingItem, ok := remaining.(httpsfv.Item)
	if !ok {
		return Header{}, errors.New("aauth budgets: remaining must be an integer item")
	}
	header.Remaining, ok = remainingItem.Value.(int64)
	if !ok {
		return Header{}, errors.New("aauth budgets: remaining must be an integer")
	}
	for _, member := range []struct {
		name   string
		target **int64
	}{{"cost", &header.Cost}, {"reserved", &header.Reserved}, {"required", &header.Required}, {"decimals", &header.Decimals}} {
		value, present := dictionary.Get(member.name)
		if !present {
			continue
		}
		item, ok := value.(httpsfv.Item)
		integer, integerOK := item.Value.(int64)
		if !ok || !integerOK {
			return Header{}, fmt.Errorf("aauth budgets: %s must be an integer", member.name)
		}
		copy := integer
		*member.target = &copy
	}
	if value, present := dictionary.Get("unit"); present {
		item, ok := value.(httpsfv.Item)
		unit, unitOK := item.Value.(string)
		if !ok || !unitOK {
			return Header{}, errors.New("aauth budgets: unit must be a string")
		}
		header.Unit = unit
	}
	if err := validateHeader(header); err != nil {
		return Header{}, err
	}
	return header, nil
}

func validateHeader(header Header) error {
	if header.Remaining < 0 || header.Remaining > MaxAmount {
		return errors.New("aauth budgets: remaining is outside the Structured Field integer range")
	}
	if header.Cost != nil && header.Reserved != nil {
		return errors.New("aauth budgets: AAuth-Budget cannot carry both cost and reserved")
	}
	for _, value := range []*int64{header.Cost, header.Reserved, header.Required, header.Decimals} {
		if value != nil && (*value < 0 || *value > MaxAmount) {
			return errors.New("aauth budgets: AAuth-Budget integer is outside the permitted range")
		}
	}
	if (header.Unit == "") != (header.Decimals == nil) {
		return errors.New("aauth budgets: unit and decimals must appear together")
	}
	return nil
}
