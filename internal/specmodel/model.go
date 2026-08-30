// Package specmodel exposes the checked-in map from pinned editor-source
// headings to implementation ownership and proof seams.
//
// It is internal because the map supports this implementation's maintenance;
// it is not an AAuth protocol API.
package specmodel

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

//go:embed model.json
var modelJSON []byte

// Source identifies one exact editor source represented by the model.
type Source struct {
	ID           string `json:"id"`
	File         string `json:"file"`
	Commit       string `json:"commit"`
	SHA256       string `json:"sha256"`
	LineCount    int    `json:"line_count"`
	HeadingCount int    `json:"heading_count"`
	Authority    string `json:"authority"`
}

// SourceReference identifies the exact source lines supporting a tension.
type SourceReference struct {
	Source string `json:"source"`
	Lines  []int  `json:"lines"`
}

// SourceTension records a choice needed where the pinned sources disagree,
// omit a binding needed by the described flow, or explicitly leave a feature
// provisional.
type SourceTension struct {
	ID          string            `json:"id"`
	FeedbackID  string            `json:"feedback_id,omitempty"`
	Subject     string            `json:"subject"`
	Status      string            `json:"status"`
	Disposition string            `json:"disposition"`
	Grounding   string            `json:"grounding"`
	References  []SourceReference `json:"references"`
	Blocks      []string          `json:"blocks,omitempty"`
}

// Heading maps one source heading to one capability, protocol-value package,
// state-owning role, role-behavior package, and proof seam. Heading ranges are
// consecutive and non-overlapping; the source's Markdown levels retain the
// hierarchy without duplicating requirement prose.
type Heading struct {
	Source               string `json:"source"`
	Heading              string `json:"heading"`
	Line                 int    `json:"line"`
	End                  int    `json:"end"`
	Classification       string `json:"classification"`
	CapabilityID         string `json:"capability_id"`
	ValuePackage         string `json:"value_package"`
	StateOwnerRole       string `json:"state_owner_role"`
	BehaviorOwnerPackage string `json:"behavior_owner_package"`
	ProofSeam            string `json:"proof_seam"`
	ProofDetail          string `json:"proof_detail"`
	ExtractionNote       string `json:"extraction_note,omitempty"`
}

// Requirement identifies one uppercase normative or field-presence occurrence
// in an exact source line. The source text remains authoritative; this record
// binds that occurrence to its owning capability and proof seam without
// paraphrasing it into a second specification.
type Requirement struct {
	ID           string   `json:"id"`
	Source       string   `json:"source"`
	Line         int      `json:"line"`
	Occurrence   int      `json:"occurrence"`
	Strength     string   `json:"strength"`
	Kind         string   `json:"kind"`
	Authority    string   `json:"authority"`
	LineSHA256   string   `json:"line_sha256"`
	HeadingLine  int      `json:"heading_line"`
	Dependencies []string `json:"dependencies,omitempty"`
}

// Model is the complete checked-in protocol heading map.
type Model struct {
	Schema         string          `json:"schema"`
	Sources        []Source        `json:"sources"`
	SourceTensions []SourceTension `json:"source_tensions"`
	Headings       []Heading       `json:"headings"`
	Requirements   []Requirement   `json:"requirements"`
}

// Load decodes and validates the embedded model.
func Load() (Model, error) {
	var model Model
	if err := json.Unmarshal(modelJSON, &model); err != nil {
		return Model{}, fmt.Errorf("decode protocol model: %w", err)
	}
	if err := Validate(model); err != nil {
		return Model{}, err
	}
	return model, nil
}

// Validate checks structural properties that keep source coverage honest.
func Validate(model Model) error {
	if model.Schema != "aauth.protocol-heading-map.v1" {
		return fmt.Errorf("protocol model schema is %q", model.Schema)
	}
	if len(model.Sources) == 0 {
		return errors.New("protocol model has no sources")
	}

	sources := make(map[string]Source, len(model.Sources))
	for _, source := range model.Sources {
		if source.ID == "" || source.File == "" || source.Commit == "" || source.SHA256 == "" {
			return fmt.Errorf("protocol source has incomplete identity: %+v", source)
		}
		if source.LineCount <= 0 || source.HeadingCount <= 0 {
			return fmt.Errorf("protocol source %s has invalid line or heading count", source.ID)
		}
		if _, duplicate := sources[source.ID]; duplicate {
			return fmt.Errorf("protocol source %s is repeated", source.ID)
		}
		sources[source.ID] = source
	}

	allowedPackages := map[string]bool{
		"none": true, "aauth": true, "signaturekey": true,
		"r3": true, "events": true, "budgets": true,
		"integration": true, "agentprovider": true, "agent": true,
		"personserver": true, "resource": true, "accessserver": true,
	}
	allowedClassifications := map[string]bool{
		"normative": true, "registry": true, "provisional": true,
		"informational": true, "context": true, "example": true,
		"history": true, "rationale": true, "out_of_scope": true,
	}
	allowedStateOwners := map[string]bool{
		"none": true, "agent": true, "agent_provider": true,
		"person_server": true, "resource": true, "access_server": true,
		"verifier": true, "issuer": true, "server": true, "all_roles": true,
	}
	allowedProofSeams := map[string]bool{
		"none": true, "documentation": true, "unit": true,
		"store_contract": true, "integration": true,
		"journey": true, "interoperability": true,
	}
	behaviorOwnerForRole := map[string]string{
		"none": "none", "agent": "agent", "agent_provider": "agentprovider",
		"person_server": "personserver", "resource": "resource",
		"access_server": "accessserver", "verifier": "none",
		"issuer": "none", "server": "none", "all_roles": "none",
	}
	ownerForSource := map[string]string{
		"core": "aauth", "signature_key": "signaturekey",
		"r3": "r3", "events": "events", "budgets": "budgets",
	}
	needsOwner := func(classification string) bool {
		switch classification {
		case "normative", "registry", "provisional":
			return true
		default:
			return false
		}
	}

	counts := make(map[string]int, len(sources))
	coordinates := make(map[string]struct{}, len(model.Headings))
	bySource := make(map[string][]Heading, len(sources))
	for _, heading := range model.Headings {
		if _, ok := sources[heading.Source]; !ok {
			return fmt.Errorf("heading %q names unknown source %q", heading.Heading, heading.Source)
		}
		if heading.Heading == "" || heading.CapabilityID == "" || heading.Classification == "" || heading.ProofSeam == "" || heading.ProofDetail == "" {
			return fmt.Errorf("heading at %s:%d is incomplete", heading.Source, heading.Line)
		}
		if !allowedClassifications[heading.Classification] {
			return fmt.Errorf("heading %s:%d has unknown classification %q", heading.Source, heading.Line, heading.Classification)
		}
		if !allowedStateOwners[heading.StateOwnerRole] {
			return fmt.Errorf("heading %s:%d has unknown state owner %q", heading.Source, heading.Line, heading.StateOwnerRole)
		}
		if !allowedProofSeams[heading.ProofSeam] {
			return fmt.Errorf("heading %s:%d has unknown proof seam %q", heading.Source, heading.Line, heading.ProofSeam)
		}
		if heading.Line <= 0 || heading.End < heading.Line {
			return fmt.Errorf("heading %s:%d has invalid range through %d", heading.Source, heading.Line, heading.End)
		}
		if heading.End > sources[heading.Source].LineCount {
			return fmt.Errorf("heading %s:%d ends beyond source line count %d", heading.Source, heading.Line, sources[heading.Source].LineCount)
		}
		if !allowedPackages[heading.ValuePackage] || !allowedPackages[heading.BehaviorOwnerPackage] {
			return fmt.Errorf("heading %s:%d names an unknown package", heading.Source, heading.Line)
		}
		if needsOwner(heading.Classification) && heading.ValuePackage == "none" {
			return fmt.Errorf("%s heading %s:%d has no package owner", heading.Classification, heading.Source, heading.Line)
		}
		if expected := ownerForSource[heading.Source]; needsOwner(heading.Classification) && expected != "" && heading.ValuePackage != expected {
			return fmt.Errorf("heading %s:%d value owner is %q, want %q", heading.Source, heading.Line, heading.ValuePackage, expected)
		}
		if expected := behaviorOwnerForRole[heading.StateOwnerRole]; heading.BehaviorOwnerPackage != expected {
			return fmt.Errorf("heading %s:%d behavior owner is %q, want %q for role %q", heading.Source, heading.Line, heading.BehaviorOwnerPackage, expected, heading.StateOwnerRole)
		}
		key := fmt.Sprintf("%s:%d", heading.Source, heading.Line)
		if _, duplicate := coordinates[key]; duplicate {
			return fmt.Errorf("heading coordinate %s is repeated", key)
		}
		coordinates[key] = struct{}{}
		counts[heading.Source]++
		bySource[heading.Source] = append(bySource[heading.Source], heading)
	}

	for id, source := range sources {
		if counts[id] != source.HeadingCount {
			return fmt.Errorf("source %s maps %d headings, want %d", id, counts[id], source.HeadingCount)
		}
		headings := bySource[id]
		sort.Slice(headings, func(i, j int) bool { return headings[i].Line < headings[j].Line })
		for index := 1; index < len(headings); index++ {
			if headings[index].Line != headings[index-1].End+1 {
				return fmt.Errorf("source %s has a heading-map gap or overlap between lines %d and %d", id, headings[index-1].End, headings[index].Line)
			}
		}
		if headings[len(headings)-1].End != source.LineCount {
			return fmt.Errorf("source %s heading map ends at %d, want %d", id, headings[len(headings)-1].End, source.LineCount)
		}
	}

	allowedStrengths := map[string]string{
		"MUST": "bcp14", "MUST NOT": "bcp14", "SHOULD": "bcp14",
		"SHOULD NOT": "bcp14", "MAY": "bcp14",
		"REQUIRED": "field_presence", "RECOMMENDED": "field_presence",
		"OPTIONAL": "field_presence",
	}
	allowedAuthorities := map[string]bool{
		"normative": true, "provisional": true, "informational": true,
	}
	allowedDependencies := map[string]bool{"asyncapi": true}
	for id := range sources {
		allowedDependencies[id] = true
	}
	requirementIDs := make(map[string]struct{}, len(model.Requirements))
	requirementCoordinates := make(map[string]struct{}, len(model.Requirements))
	for _, requirement := range model.Requirements {
		source, ok := sources[requirement.Source]
		if !ok || requirement.Line <= 0 || requirement.Line > source.LineCount || requirement.Occurrence <= 0 {
			return fmt.Errorf("requirement %s has an invalid source coordinate", requirement.ID)
		}
		kind, ok := allowedStrengths[requirement.Strength]
		if !ok || requirement.Kind != kind || !allowedAuthorities[requirement.Authority] {
			return fmt.Errorf("requirement %s has an invalid strength, kind, or authority", requirement.ID)
		}
		if len(requirement.LineSHA256) != 64 {
			return fmt.Errorf("requirement %s has an invalid line digest", requirement.ID)
		}
		if _, err := hex.DecodeString(requirement.LineSHA256); err != nil {
			return fmt.Errorf("requirement %s has a non-hex line digest", requirement.ID)
		}
		if _, duplicate := requirementIDs[requirement.ID]; duplicate || requirement.ID == "" {
			return fmt.Errorf("requirement ID %q is empty or repeated", requirement.ID)
		}
		requirementIDs[requirement.ID] = struct{}{}
		coordinate := fmt.Sprintf("%s:%d:%d", requirement.Source, requirement.Line, requirement.Occurrence)
		if _, duplicate := requirementCoordinates[coordinate]; duplicate {
			return fmt.Errorf("requirement coordinate %s is repeated", coordinate)
		}
		requirementCoordinates[coordinate] = struct{}{}
		var owner *Heading
		for index := range bySource[requirement.Source] {
			heading := &bySource[requirement.Source][index]
			if heading.Line <= requirement.Line && requirement.Line <= heading.End {
				owner = heading
				break
			}
		}
		if owner == nil || requirement.HeadingLine != owner.Line {
			return fmt.Errorf("requirement %s does not match its heading owner", requirement.ID)
		}
		expectedAuthority := "informational"
		if owner.Classification == "normative" || owner.Classification == "registry" {
			expectedAuthority = "normative"
		} else if owner.Classification == "provisional" {
			expectedAuthority = "provisional"
		}
		if requirement.Authority != expectedAuthority {
			return fmt.Errorf("requirement %s authority is %q, want %q from its heading", requirement.ID, requirement.Authority, expectedAuthority)
		}
		if requirement.Authority != "informational" && owner.ValuePackage == "none" {
			return fmt.Errorf("requirement %s resolves to no value-package owner", requirement.ID)
		}
		seenDependencies := make(map[string]bool, len(requirement.Dependencies))
		for _, dependency := range requirement.Dependencies {
			if !allowedDependencies[dependency] || seenDependencies[dependency] {
				return fmt.Errorf("requirement %s has invalid dependency %q", requirement.ID, dependency)
			}
			seenDependencies[dependency] = true
		}
	}

	tensions := make(map[string]struct{}, len(model.SourceTensions))
	allowedTensionStatuses := map[string]bool{
		"implementation_choice": true, "unresolved": true, "provisional": true,
	}
	for _, tension := range model.SourceTensions {
		if tension.ID == "" || tension.Subject == "" || tension.Disposition == "" || tension.Grounding == "" || len(tension.References) == 0 {
			return fmt.Errorf("source tension is incomplete: %+v", tension)
		}
		if !allowedTensionStatuses[tension.Status] {
			return fmt.Errorf("source tension %s has unknown status %q", tension.ID, tension.Status)
		}
		if _, duplicate := tensions[tension.ID]; duplicate {
			return fmt.Errorf("source tension %s is repeated", tension.ID)
		}
		tensions[tension.ID] = struct{}{}
		for _, reference := range tension.References {
			source, ok := sources[reference.Source]
			if !ok || len(reference.Lines) == 0 {
				return fmt.Errorf("source tension %s has an invalid source reference", tension.ID)
			}
			for _, line := range reference.Lines {
				if line <= 0 || line > source.LineCount {
					return fmt.Errorf("source tension %s references invalid %s line %d", tension.ID, reference.Source, line)
				}
			}
		}
	}

	return nil
}
