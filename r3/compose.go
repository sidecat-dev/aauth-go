package r3

import (
	"errors"
	"slices"
	"strings"
)

// MergeDisplays combines the display sections of several R3 definitions into
// one, for a document composed from operations those definitions cover, as
// R3 Operations Spanning Multiple Definitions allows. Summaries are joined
// with "; ", and implications and irreversible with a blank line, so every
// consequence each definition states is kept. data_accessed is the union of
// the distinct values, joined with "; ". A repeated value is kept once, and
// a display that merges one other is that display unchanged.
func MergeDisplays(displays ...Display) (Display, error) {
	if len(displays) == 0 {
		return Display{}, errors.New("r3: at least one display is required")
	}
	for _, display := range displays {
		if err := display.validate(); err != nil {
			return Display{}, err
		}
	}
	collect := func(member func(Display) string, separator string) string {
		var values []string
		for _, display := range displays {
			value := member(display)
			if strings.TrimSpace(value) != "" && !slices.Contains(values, value) {
				values = append(values, value)
			}
		}
		return strings.Join(values, separator)
	}
	return NewDisplay(
		collect(Display.Summary, "; "),
		collect(Display.Implications, "\n\n"),
		collect(Display.DataAccessed, "; "),
		collect(Display.Irreversible, "\n\n"),
	)
}
