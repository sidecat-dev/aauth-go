package specmodel

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

var (
	headingPattern  = regexp.MustCompile(`^\.?#{1,6}[ \t]+(.+)$`)
	headingAnchor   = regexp.MustCompile(` \{#[^}]+\}$`)
	requirementWord = regexp.MustCompile(`\b(?:MUST NOT|SHOULD NOT|MUST|SHOULD|MAY|REQUIRED|RECOMMENDED|OPTIONAL)\b`)
)

// VerifySourceDirectory recomputes source digests, line counts, normalized
// heading coordinates, and heading ranges from the exact editor-source files
// in directory.
func VerifySourceDirectory(model Model, directory string) error {
	return verifySourceDirectory(model, directory, true)
}

func verifySourceDirectory(model Model, directory string, verifyRequirements bool) error {
	if err := Validate(model); err != nil {
		return err
	}
	if directory == "" {
		return errors.New("protocol source directory is required")
	}

	headingsBySource := make(map[string][]Heading, len(model.Sources))
	for _, heading := range model.Headings {
		headingsBySource[heading.Source] = append(headingsBySource[heading.Source], heading)
	}
	for _, source := range model.Sources {
		if filepath.Base(source.File) != source.File {
			return fmt.Errorf("protocol source %s file is not a base name", source.ID)
		}
		path := filepath.Join(directory, source.File)
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read protocol source %s: %w", source.ID, err)
		}
		digest := sha256.Sum256(data)
		if observed := hex.EncodeToString(digest[:]); observed != source.SHA256 {
			return fmt.Errorf("protocol source %s digest is %s, want %s", source.ID, observed, source.SHA256)
		}

		lineCount := bytes.Count(data, []byte{'\n'})
		if len(data) != 0 && data[len(data)-1] != '\n' {
			lineCount++
		}
		if lineCount != source.LineCount {
			return fmt.Errorf("protocol source %s has %d lines, want %d", source.ID, lineCount, source.LineCount)
		}

		type sourceHeading struct {
			line  int
			title string
		}
		var observed []sourceHeading
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
		line := 0
		for scanner.Scan() {
			line++
			match := headingPattern.FindStringSubmatch(scanner.Text())
			if match == nil {
				continue
			}
			observed = append(observed, sourceHeading{
				line:  line,
				title: headingAnchor.ReplaceAllString(match[1], ""),
			})
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("scan protocol source %s: %w", source.ID, err)
		}

		expected := append([]Heading(nil), headingsBySource[source.ID]...)
		sort.Slice(expected, func(i, j int) bool { return expected[i].Line < expected[j].Line })
		if len(observed) != len(expected) {
			return fmt.Errorf("protocol source %s has %d headings, model has %d", source.ID, len(observed), len(expected))
		}
		for index := range observed {
			if observed[index].line != expected[index].Line || observed[index].title != expected[index].Heading {
				return fmt.Errorf(
					"protocol source %s heading %d is %d %q, want %d %q",
					source.ID, index+1, observed[index].line, observed[index].title,
					expected[index].Line, expected[index].Heading,
				)
			}
			wantEnd := source.LineCount
			if index+1 < len(observed) {
				wantEnd = observed[index+1].line - 1
			}
			if expected[index].End != wantEnd {
				return fmt.Errorf("protocol source %s heading at line %d ends at %d, want %d", source.ID, expected[index].Line, expected[index].End, wantEnd)
			}
		}
	}
	if verifyRequirements {
		if len(model.Requirements) == 0 {
			return errors.New("protocol model has no requirement occurrences")
		}
		observed, err := extractRequirements(model, directory)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(observed, model.Requirements) {
			limit := len(observed)
			if len(model.Requirements) < limit {
				limit = len(model.Requirements)
			}
			for index := 0; index < limit; index++ {
				if !reflect.DeepEqual(observed[index], model.Requirements[index]) {
					return fmt.Errorf("requirement occurrence %d differs: observed %+v, model %+v", index, observed[index], model.Requirements[index])
				}
			}
			return fmt.Errorf("source yields %d requirement occurrences, model has %d", len(observed), len(model.Requirements))
		}
	}
	return nil
}

// ExtractRequirements derives the exact normative and field-presence
// occurrences from a verified source directory. Informational occurrences are
// retained and labelled so source examples or history cannot silently become
// implementation requirements.
func ExtractRequirements(model Model, directory string) ([]Requirement, error) {
	if err := verifySourceDirectory(model, directory, false); err != nil {
		return nil, err
	}
	return extractRequirements(model, directory)
}

func extractRequirements(model Model, directory string) ([]Requirement, error) {
	headingsBySource := make(map[string][]Heading, len(model.Sources))
	for _, heading := range model.Headings {
		headingsBySource[heading.Source] = append(headingsBySource[heading.Source], heading)
	}
	for source := range headingsBySource {
		sort.Slice(headingsBySource[source], func(i, j int) bool {
			return headingsBySource[source][i].Line < headingsBySource[source][j].Line
		})
	}

	var result []Requirement
	for _, source := range model.Sources {
		data, err := os.ReadFile(filepath.Join(directory, source.File))
		if err != nil {
			return nil, fmt.Errorf("read protocol source %s: %w", source.ID, err)
		}
		lines := bytes.Split(data, []byte{'\n'})
		if len(lines) != 0 && len(lines[len(lines)-1]) == 0 {
			lines = lines[:len(lines)-1]
		}
		headings := headingsBySource[source.ID]
		headingIndex := 0
		for index, lineBytes := range lines {
			lineNumber := index + 1
			matches := requirementWord.FindAllString(string(lineBytes), -1)
			if len(matches) == 0 {
				continue
			}
			for headingIndex+1 < len(headings) && headings[headingIndex+1].Line <= lineNumber {
				headingIndex++
			}
			if len(headings) == 0 || lineNumber < headings[headingIndex].Line || lineNumber > headings[headingIndex].End {
				return nil, fmt.Errorf("protocol source %s line %d has a requirement outside a mapped heading", source.ID, lineNumber)
			}
			heading := headings[headingIndex]
			digest := sha256.Sum256(lineBytes)
			for occurrence, strength := range matches {
				kind := "bcp14"
				if strength == "REQUIRED" || strength == "RECOMMENDED" || strength == "OPTIONAL" {
					kind = "field_presence"
				}
				authority := "informational"
				if heading.Classification == "normative" || heading.Classification == "registry" {
					authority = "normative"
				} else if heading.Classification == "provisional" {
					authority = "provisional"
				}
				result = append(result, Requirement{
					ID:     fmt.Sprintf("%s-L%06d-O%02d-%s", requirementPrefix(source.ID), lineNumber, occurrence+1, strings.ReplaceAll(strength, " ", "_")),
					Source: source.ID, Line: lineNumber, Occurrence: occurrence + 1,
					Strength: strength, Kind: kind, Authority: authority,
					LineSHA256: hex.EncodeToString(digest[:]), HeadingLine: heading.Line,
					Dependencies: requirementDependencies(source.ID, lineNumber),
				})
			}
		}
	}
	return result, nil
}

func requirementPrefix(source string) string {
	switch source {
	case "signature_key":
		return "SIGKEY"
	case "bootstrap":
		return "BOOT"
	case "budgets":
		return "BUDGET"
	case "interop":
		return "INTEROP"
	default:
		return strings.ToUpper(source)
	}
}

func requirementDependencies(source string, line int) []string {
	switch source {
	case "core":
		if 2626 <= line && line <= 2761 {
			return []string{"signature_key"}
		}
	case "r3":
		dependencies := []string{"core"}
		if 298 <= line && line <= 304 {
			dependencies = append(dependencies, "budgets")
		}
		if 428 <= line && line <= 443 || 688 <= line && line <= 697 {
			dependencies = append(dependencies, "signature_key")
		}
		if 215 <= line && line <= 234 {
			dependencies = append(dependencies, "events")
		}
		return dependencies
	case "events":
		dependencies := []string{"core", "signature_key"}
		if line >= 458 {
			dependencies = append(dependencies, "r3", "asyncapi")
		}
		return dependencies
	case "budgets":
		dependencies := []string{"core"}
		if 419 <= line && line <= 427 {
			dependencies = append(dependencies, "r3")
		}
		return dependencies
	case "bootstrap", "interop":
		return []string{"core", "signature_key"}
	}
	return nil
}

// VerifyManifest requires each source file, commit, and digest to occur
// together in exactly one Markdown table row.
func VerifyManifest(model Model, markdown []byte) error {
	if len(markdown) == 0 {
		return errors.New("specification manifest is empty")
	}
	rows := strings.Split(string(markdown), "\n")
	for _, source := range model.Sources {
		matchingRows := 0
		for _, row := range rows {
			if !strings.HasPrefix(strings.TrimSpace(row), "|") || !strings.Contains(row, source.File) {
				continue
			}
			matchingRows++
			if !strings.Contains(row, source.Commit) || !strings.Contains(row, source.SHA256) {
				return fmt.Errorf("manifest row for %s does not bind its file, commit, and digest", source.ID)
			}
		}
		if matchingRows != 1 {
			return fmt.Errorf("manifest contains %d rows for %s, want one", matchingRows, source.ID)
		}
	}
	return nil
}
