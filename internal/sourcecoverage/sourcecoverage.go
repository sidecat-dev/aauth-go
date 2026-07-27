package sourcecoverage

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"html"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

const (
	ManifestSchema  = "aauth.source-coverage.v0"
	InventorySchema = "aauth.source-section-inventory.v0"

	SourceMarkdown = "markdown"
	SourceHTML     = "html"

	StatusExercised     = "exercised"
	StatusPartial       = "partial"
	StatusUnsupported   = "unsupported"
	StatusInformational = "informational"
	StatusUnclaimed     = "unclaimed"
)

type Manifest struct {
	Schema      string       `json:"schema"`
	Profile     string       `json:"profile"`
	Sources     []Source     `json:"sources"`
	Annotations []Annotation `json:"annotations"`
}

type Source struct {
	ID       string `json:"id"`
	Revision string `json:"revision"`
	Filename string `json:"filename"`
	Format   string `json:"format"`
	SHA256   string `json:"sha256"`
}

type Annotation struct {
	Source   string     `json:"source"`
	Section  string     `json:"section"`
	Status   string     `json:"status"`
	Claim    string     `json:"claim"`
	Evidence []Evidence `json:"evidence,omitempty"`
}

type Evidence struct {
	File string `json:"file"`
	Test string `json:"test"`
}

type Inventory struct {
	Schema  string            `json:"schema"`
	Sources []InventorySource `json:"sources"`
}

type InventorySource struct {
	ID       string    `json:"id"`
	Sections []Section `json:"sections"`
}

type Section struct {
	ID    string `json:"id"`
	Level int    `json:"level"`
	Title string `json:"title"`
}

type Bundle struct {
	Manifest  Manifest
	Inventory Inventory
}

func Load(manifestBody, inventoryBody []byte) (Bundle, error) {
	var bundle Bundle
	manifest, err := DecodeManifest(manifestBody)
	if err != nil {
		return Bundle{}, err
	}
	bundle.Manifest = manifest
	if err := decodeSingleJSON(inventoryBody, &bundle.Inventory); err != nil {
		return Bundle{}, fmt.Errorf("source coverage inventory: %w", err)
	}
	if err := bundle.Validate(); err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}

func DecodeManifest(body []byte) (Manifest, error) {
	var manifest Manifest
	if err := decodeSingleJSON(body, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("source coverage manifest: %w", err)
	}
	if manifest.Schema != ManifestSchema {
		return Manifest{}, errors.New("source coverage manifest schema is invalid")
	}
	if strings.TrimSpace(manifest.Profile) != manifest.Profile ||
		manifest.Profile == "" {
		return Manifest{}, errors.New("source coverage profile is invalid")
	}
	if len(manifest.Sources) == 0 {
		return Manifest{}, errors.New("source coverage requires at least one source")
	}
	return manifest, nil
}

func LoadFiles(manifestPath, inventoryPath string) (Bundle, error) {
	manifestBody, err := os.ReadFile(manifestPath)
	if err != nil {
		return Bundle{}, fmt.Errorf("read source coverage manifest: %w", err)
	}
	inventoryBody, err := os.ReadFile(inventoryPath)
	if err != nil {
		return Bundle{}, fmt.Errorf("read source coverage inventory: %w", err)
	}
	return Load(manifestBody, inventoryBody)
}

func (bundle Bundle) Validate() error {
	if bundle.Manifest.Schema != ManifestSchema {
		return errors.New("source coverage manifest schema is invalid")
	}
	if strings.TrimSpace(bundle.Manifest.Profile) != bundle.Manifest.Profile ||
		bundle.Manifest.Profile == "" {
		return errors.New("source coverage profile is invalid")
	}
	if bundle.Inventory.Schema != InventorySchema {
		return errors.New("source coverage inventory schema is invalid")
	}
	if len(bundle.Manifest.Sources) == 0 {
		return errors.New("source coverage requires at least one source")
	}
	if len(bundle.Manifest.Sources) != len(bundle.Inventory.Sources) {
		return errors.New("source coverage source and inventory counts differ")
	}

	sourceSections := make(map[string]map[string]struct{}, len(bundle.Manifest.Sources))
	for index, source := range bundle.Manifest.Sources {
		if strings.TrimSpace(source.ID) != source.ID || source.ID == "" {
			return errors.New("source coverage source id is invalid")
		}
		if _, duplicate := sourceSections[source.ID]; duplicate {
			return fmt.Errorf("source coverage source %q is duplicated", source.ID)
		}
		if strings.TrimSpace(source.Revision) != source.Revision ||
			source.Revision == "" {
			return fmt.Errorf("source coverage source %q revision is invalid", source.ID)
		}
		if filepath.Base(source.Filename) != source.Filename ||
			source.Filename == "." ||
			source.Filename == "" {
			return fmt.Errorf("source coverage source %q filename is invalid", source.ID)
		}
		if source.Format != SourceMarkdown && source.Format != SourceHTML {
			return fmt.Errorf("source coverage source %q format is invalid", source.ID)
		}
		if !lowerHexDigest(source.SHA256) {
			return fmt.Errorf("source coverage source %q digest is invalid", source.ID)
		}
		inventorySource := bundle.Inventory.Sources[index]
		if inventorySource.ID != source.ID {
			return errors.New("source coverage source and inventory order differ")
		}
		if len(inventorySource.Sections) == 0 {
			return fmt.Errorf("source coverage source %q has no sections", source.ID)
		}
		sections := make(map[string]struct{}, len(inventorySource.Sections))
		for _, section := range inventorySource.Sections {
			if strings.TrimSpace(section.ID) != section.ID || section.ID == "" ||
				strings.TrimSpace(section.Title) != section.Title ||
				section.Title == "" ||
				section.Level < 1 ||
				section.Level > 6 {
				return fmt.Errorf(
					"source coverage source %q contains an invalid section",
					source.ID,
				)
			}
			if _, duplicate := sections[section.ID]; duplicate {
				return fmt.Errorf(
					"source coverage source %q section %q is duplicated",
					source.ID,
					section.ID,
				)
			}
			sections[section.ID] = struct{}{}
		}
		sourceSections[source.ID] = sections
	}

	seenAnnotations := make(map[string]struct{}, len(bundle.Manifest.Annotations))
	for _, annotation := range bundle.Manifest.Annotations {
		sections, knownSource := sourceSections[annotation.Source]
		if !knownSource {
			return fmt.Errorf(
				"source coverage annotation names unknown source %q",
				annotation.Source,
			)
		}
		if _, knownSection := sections[annotation.Section]; !knownSection {
			return fmt.Errorf(
				"source coverage annotation names unknown section %q/%q",
				annotation.Source,
				annotation.Section,
			)
		}
		key := annotation.Source + "\x00" + annotation.Section
		if _, duplicate := seenAnnotations[key]; duplicate {
			return fmt.Errorf(
				"source coverage has duplicate annotation %q/%q",
				annotation.Source,
				annotation.Section,
			)
		}
		seenAnnotations[key] = struct{}{}
		if strings.TrimSpace(annotation.Claim) != annotation.Claim ||
			annotation.Claim == "" {
			return fmt.Errorf(
				"source coverage annotation %q/%q claim is invalid",
				annotation.Source,
				annotation.Section,
			)
		}
		switch annotation.Status {
		case StatusExercised, StatusPartial:
			if len(annotation.Evidence) == 0 {
				return fmt.Errorf(
					"source coverage annotation %q/%q requires evidence",
					annotation.Source,
					annotation.Section,
				)
			}
		case StatusUnsupported, StatusInformational:
			if len(annotation.Evidence) != 0 {
				return fmt.Errorf(
					"source coverage annotation %q/%q with status %q must not cite evidence",
					annotation.Source,
					annotation.Section,
					annotation.Status,
				)
			}
		default:
			return fmt.Errorf(
				"source coverage annotation %q/%q status is invalid",
				annotation.Source,
				annotation.Section,
			)
		}
		for _, evidence := range annotation.Evidence {
			if err := validateEvidenceReference(evidence); err != nil {
				return fmt.Errorf(
					"source coverage annotation %q/%q: %w",
					annotation.Source,
					annotation.Section,
					err,
				)
			}
		}
	}
	return nil
}

func (bundle Bundle) VerifySources(sourceDir string) error {
	if err := bundle.Validate(); err != nil {
		return err
	}
	for index, source := range bundle.Manifest.Sources {
		body, err := os.ReadFile(filepath.Join(sourceDir, source.Filename))
		if err != nil {
			return fmt.Errorf("source coverage read %q: %w", source.Filename, err)
		}
		digest := sha256.Sum256(body)
		if hex.EncodeToString(digest[:]) != source.SHA256 {
			return fmt.Errorf(
				"source coverage source digest differs for %q",
				source.ID,
			)
		}
		sections, err := ExtractSections(source.Format, body)
		if err != nil {
			return fmt.Errorf(
				"source coverage extract sections from %q: %w",
				source.ID,
				err,
			)
		}
		if !reflect.DeepEqual(sections, bundle.Inventory.Sources[index].Sections) {
			return fmt.Errorf(
				"source coverage section inventory differs for %q",
				source.ID,
			)
		}
	}
	return nil
}

func (bundle Bundle) VerifyEvidence(repoDir string) error {
	if err := bundle.Validate(); err != nil {
		return err
	}
	testsByFile := make(map[string]map[string]struct{})
	for _, annotation := range bundle.Manifest.Annotations {
		for _, evidence := range annotation.Evidence {
			tests, loaded := testsByFile[evidence.File]
			if !loaded {
				path := filepath.Join(repoDir, filepath.FromSlash(evidence.File))
				file, err := parser.ParseFile(
					token.NewFileSet(),
					path,
					nil,
					parser.SkipObjectResolution,
				)
				if err != nil {
					return fmt.Errorf(
						"source coverage parse evidence file %q: %w",
						evidence.File,
						err,
					)
				}
				tests = make(map[string]struct{})
				for _, declaration := range file.Decls {
					function, ok := declaration.(*ast.FuncDecl)
					if !ok || function.Recv != nil ||
						!strings.HasPrefix(function.Name.Name, "Test") {
						continue
					}
					tests[function.Name.Name] = struct{}{}
				}
				testsByFile[evidence.File] = tests
			}
			if _, exists := tests[evidence.Test]; !exists {
				return fmt.Errorf(
					"source coverage evidence %s:%s does not exist",
					evidence.File,
					evidence.Test,
				)
			}
		}
	}
	return nil
}

func BuildInventory(manifest Manifest, sourceDir string) (Inventory, error) {
	inventory := Inventory{
		Schema:  InventorySchema,
		Sources: make([]InventorySource, 0, len(manifest.Sources)),
	}
	for _, source := range manifest.Sources {
		body, err := os.ReadFile(filepath.Join(sourceDir, source.Filename))
		if err != nil {
			return Inventory{}, fmt.Errorf("read %q: %w", source.Filename, err)
		}
		digest := sha256.Sum256(body)
		if hex.EncodeToString(digest[:]) != source.SHA256 {
			return Inventory{}, fmt.Errorf(
				"source digest differs for %q",
				source.ID,
			)
		}
		sections, err := ExtractSections(source.Format, body)
		if err != nil {
			return Inventory{}, fmt.Errorf(
				"extract sections from %q: %w",
				source.ID,
				err,
			)
		}
		inventory.Sources = append(inventory.Sources, InventorySource{
			ID:       source.ID,
			Sections: sections,
		})
	}
	return inventory, nil
}

func EncodeInventory(inventory Inventory) ([]byte, error) {
	body, err := json.MarshalIndent(inventory, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

func (bundle Bundle) RenderMarkdown() ([]byte, error) {
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	annotations := make(map[string]Annotation, len(bundle.Manifest.Annotations))
	for _, annotation := range bundle.Manifest.Annotations {
		annotations[annotation.Source+"\x00"+annotation.Section] = annotation
	}
	counts := map[string]int{
		StatusExercised:     0,
		StatusPartial:       0,
		StatusUnsupported:   0,
		StatusInformational: 0,
		StatusUnclaimed:     0,
	}
	sourceCounts := make(map[string]map[string]int, len(bundle.Manifest.Sources))
	for _, source := range bundle.Inventory.Sources {
		sourceCounts[source.ID] = map[string]int{
			StatusExercised:     0,
			StatusPartial:       0,
			StatusUnsupported:   0,
			StatusInformational: 0,
			StatusUnclaimed:     0,
		}
		for _, section := range source.Sections {
			status := StatusUnclaimed
			if annotation, exists := annotations[source.ID+"\x00"+section.ID]; exists {
				status = annotation.Status
			}
			counts[status]++
			sourceCounts[source.ID][status]++
		}
	}

	var report strings.Builder
	report.WriteString("# AAuth Go source coverage\n\n")
	report.WriteString(
		"This generated source coverage is not a full-conformance claim. " +
			"It binds the implementation's explicit claims and omissions to " +
			"pinned source bytes and executable Go evidence.\n\n",
	)
	report.WriteString("Profile: " + bundle.Manifest.Profile + "\n\n")
	report.WriteString("## Summary\n\n")
	report.WriteString("| Status | Sections |\n| --- | ---: |\n")
	for _, status := range []string{
		StatusExercised,
		StatusPartial,
		StatusUnsupported,
		StatusInformational,
		StatusUnclaimed,
	} {
		report.WriteString("| " + statusTitle(status) + " | " +
			strconv.Itoa(counts[status]) + " |\n")
	}
	report.WriteString("\n`Unclaimed` means this module makes no section-level " +
		"implementation claim. It is visible work, not implicit support. " +
		"`Exercised` names the supported behavior claimed for that section " +
		"and binds it to a runnable test; it does not silently claim behavior " +
		"outside the written claim. `Partial` names an intentionally incomplete " +
		"implementation, and `Unsupported` names an explicit omission.\n\n")
	report.WriteString("## Pinned sources\n\n")
	report.WriteString(
		"| Source | Revision | SHA-256 | Exercised | Partial | Unsupported | Informational | Unclaimed |\n",
	)
	report.WriteString(
		"| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |\n",
	)
	for _, source := range bundle.Manifest.Sources {
		sourceStatus := sourceCounts[source.ID]
		report.WriteString("| `" + source.ID + "` | " + source.Revision +
			" | `" + source.SHA256 + "` | " +
			strconv.Itoa(sourceStatus[StatusExercised]) + " | " +
			strconv.Itoa(sourceStatus[StatusPartial]) + " | " +
			strconv.Itoa(sourceStatus[StatusUnsupported]) + " | " +
			strconv.Itoa(sourceStatus[StatusInformational]) + " | " +
			strconv.Itoa(sourceStatus[StatusUnclaimed]) + " |\n")
	}
	report.WriteString("\n## Explicit section dispositions\n\n")
	sorted := append([]Annotation(nil), bundle.Manifest.Annotations...)
	sort.SliceStable(sorted, func(left, right int) bool {
		if sorted[left].Source != sorted[right].Source {
			return sorted[left].Source < sorted[right].Source
		}
		return sorted[left].Section < sorted[right].Section
	})
	for _, annotation := range sorted {
		report.WriteString("### `" + annotation.Source + "/" +
			annotation.Section + "` — " + statusTitle(annotation.Status) + "\n\n")
		report.WriteString(annotation.Claim + "\n")
		if len(annotation.Evidence) > 0 {
			report.WriteString("\nEvidence:\n\n")
			for _, evidence := range annotation.Evidence {
				report.WriteString("- `" + evidence.File + ":" +
					evidence.Test + "`\n")
			}
		}
		report.WriteString("\n")
	}
	return []byte(strings.TrimRight(report.String(), "\n") + "\n"), nil
}

var (
	markdownHeadingPattern = regexp.MustCompile(`^(#{1,6})[ \t]+(.+?)[ \t]*$`)
	explicitAnchorPattern  = regexp.MustCompile(
		`[ \t]+\{#([A-Za-z0-9._:-]+)\}[ \t]*$`,
	)
	htmlHeadingPattern = regexp.MustCompile(
		`(?is)<h([1-6])\b[^>]*\bid="([^"]+)"[^>]*>(.*?)</h[1-6]>`,
	)
	htmlTagPattern  = regexp.MustCompile(`(?is)<[^>]+>`)
	testNamePattern = regexp.MustCompile(`^Test[A-Za-z0-9_]+$`)
)

func ExtractSections(format string, body []byte) ([]Section, error) {
	switch format {
	case SourceMarkdown:
		return extractMarkdownSections(body)
	case SourceHTML:
		return extractHTMLSections(body)
	default:
		return nil, fmt.Errorf("unsupported source format %q", format)
	}
}

func extractMarkdownSections(body []byte) ([]Section, error) {
	var sections []Section
	seen := make(map[string]struct{})
	var hierarchy [6]string
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 64<<10), 4<<20)
	for scanner.Scan() {
		match := markdownHeadingPattern.FindStringSubmatch(scanner.Text())
		if match == nil {
			continue
		}
		title := strings.TrimSpace(match[2])
		level := len(match[1])
		id := ""
		if anchor := explicitAnchorPattern.FindStringSubmatch(title); anchor != nil {
			id = anchor[1]
			title = strings.TrimSpace(
				title[:len(title)-len(anchor[0])],
			)
		} else {
			id = slug(title)
			if level > 1 && hierarchy[level-2] != "" {
				id = hierarchy[level-2] + "/" + id
			}
		}
		if id == "" || title == "" {
			return nil, errors.New("markdown source has an invalid heading")
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, fmt.Errorf("markdown source has duplicate section id %q", id)
		}
		seen[id] = struct{}{}
		hierarchy[level-1] = id
		for index := level; index < len(hierarchy); index++ {
			hierarchy[index] = ""
		}
		sections = append(sections, Section{
			ID:    id,
			Level: level,
			Title: title,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(sections) == 0 {
		return nil, errors.New("markdown source contains no sections")
	}
	return sections, nil
}

func extractHTMLSections(body []byte) ([]Section, error) {
	matches := htmlHeadingPattern.FindAllSubmatch(body, -1)
	if len(matches) == 0 {
		return nil, errors.New("HTML source contains no sections")
	}
	sections := make([]Section, 0, len(matches))
	seen := make(map[string]struct{}, len(matches))
	for _, match := range matches {
		level, _ := strconv.Atoi(string(match[1]))
		id := strings.TrimSpace(string(match[2]))
		title := strings.Join(
			strings.Fields(
				html.UnescapeString(
					string(htmlTagPattern.ReplaceAll(match[3], nil)),
				),
			),
			" ",
		)
		if id == "" || title == "" {
			return nil, errors.New("HTML source has an invalid heading")
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, fmt.Errorf("HTML source has duplicate section id %q", id)
		}
		seen[id] = struct{}{}
		sections = append(sections, Section{ID: id, Level: level, Title: title})
	}
	return sections, nil
}

func slug(value string) string {
	var result strings.Builder
	pendingDash := false
	for _, character := range strings.ToLower(value) {
		if unicode.IsLetter(character) || unicode.IsDigit(character) {
			if pendingDash && result.Len() > 0 {
				result.WriteByte('-')
			}
			pendingDash = false
			result.WriteRune(character)
		} else {
			pendingDash = true
		}
	}
	return result.String()
}

func validateEvidenceReference(evidence Evidence) error {
	if evidence.File == "" ||
		filepath.IsAbs(evidence.File) ||
		filepath.ToSlash(filepath.Clean(evidence.File)) != evidence.File ||
		strings.HasPrefix(evidence.File, "../") ||
		filepath.Ext(evidence.File) != ".go" {
		return errors.New("source coverage evidence file is invalid")
	}
	if !testNamePattern.MatchString(evidence.Test) {
		return errors.New("source coverage evidence test is invalid")
	}
	return nil
}

func lowerHexDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func decodeSingleJSON(body []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON content")
	}
	return nil
}

func statusTitle(status string) string {
	if status == "" {
		return ""
	}
	return strings.ToUpper(status[:1]) + status[1:]
}
