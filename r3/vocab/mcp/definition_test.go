package mcp

import (
	"errors"
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/r3"
)

const definitionEndpoint = "https://resource.example/mcp"

func TestParseDefinitionOwnsCompletePaginatedToolsListSnapshot(t *testing.T) {
	first := []byte(`{"tools":[{"name":"calendar.read","description":"Read calendars","inputSchema":{"type":"object"},"_meta":{"aauth.dev/access-mode":"person-token"}}],"nextCursor":"page-2"}`)
	second := []byte(`{"tools":[{"name":"calendar.write","inputSchema":{"type":"object"},"_meta":{"aauth.dev/access-mode":"auth-token","aauth.dev/budget":true}}]}`)
	source := NewToolsListSnapshot(
		NewInitialToolsListPage(first),
		NewContinuedToolsListPage("page-2", second),
	)
	first[0] = '['
	second[0] = '['

	snapshot, err := ParseDefinition(definitionEndpoint, source)
	if err != nil {
		t.Fatal(err)
	}
	if got := snapshot.Vocabulary(); got != URI {
		t.Fatalf("Vocabulary() = %q, want %q", got, URI)
	}
	if got := len(snapshot.Operations().Operations()); got != 2 {
		t.Fatalf("operation count = %d, want 2", got)
	}
	tools := make([]string, 0, 2)
	for _, operation := range snapshot.Operations().Operations() {
		typed, err := FromR3(operation)
		if err != nil {
			t.Fatal(err)
		}
		tools = append(tools, typed.Tool())
	}
	if tools[0] != "calendar.read" || tools[1] != "calendar.write" {
		t.Fatalf("tools = %v", tools)
	}

	read := mustDefinitionOperation(t, "calendar.read")
	readHints, present, err := snapshot.HintsFor(read)
	if err != nil || !present {
		t.Fatalf("HintsFor(read) = %v, %v, %v", readHints, present, err)
	}
	if mode, ok := readHints.AccessMode(); !ok || mode != aauth.AccessModePersonToken {
		t.Fatalf("read access mode = %q, %v", mode, ok)
	}
	if _, ok := readHints.Budget(); ok {
		t.Fatal("read budget hint is present")
	}

	write := mustDefinitionOperation(t, "calendar.write")
	writeHints, present, err := snapshot.HintsFor(write)
	if err != nil || !present {
		t.Fatalf("HintsFor(write) = %v, %v, %v", writeHints, present, err)
	}
	if mode, ok := writeHints.AccessMode(); !ok || mode != aauth.AccessModeAuthToken {
		t.Fatalf("write access mode = %q, %v", mode, ok)
	}
	if budget, ok := writeHints.Budget(); !ok || !budget {
		t.Fatalf("write budget = %v, %v", budget, ok)
	}
}

func TestExactSourceReceiptFramesPageBoundariesAndOwnsBodies(t *testing.T) {
	firstWithSpace := []byte(`{"tools":[],"nextCursor":"page-2"} `)
	second := []byte(`{"tools":[{"name":"calendar.read","inputSchema":{"type":"object"}}]}`)
	left := NewToolsListSnapshot(
		NewInitialToolsListPage(firstWithSpace),
		NewContinuedToolsListPage("page-2", second),
	)
	leftSnapshot, err := ParseDefinition(definitionEndpoint, left)
	if err != nil {
		t.Fatal(err)
	}
	leftDigest := leftSnapshot.Receipt().Digest()
	leftBytes := leftSnapshot.Receipt().ByteLength()
	if leftSnapshot.Receipt().Encoding() != ToolsListSourceEncoding {
		t.Fatalf("source encoding = %q", leftSnapshot.Receipt().Encoding())
	}
	if leftDigest != r3.Digest(left.ReceiptInput()) || leftBytes != int64(len(left.ReceiptInput())) {
		t.Fatal("receipt does not cover the exported MCP framing")
	}

	firstWithSpace[0] = '['
	second[0] = '['
	again, err := ParseDefinition(definitionEndpoint, left)
	if err != nil {
		t.Fatal(err)
	}
	if again.Receipt().Digest() != leftDigest || again.Receipt().ByteLength() != leftBytes {
		t.Fatal("mutating constructor inputs changed the retained exact source")
	}

	right := NewToolsListSnapshot(
		NewInitialToolsListPage([]byte(`{"tools":[],"nextCursor":"page-2"}`)),
		NewContinuedToolsListPage("page-2", []byte(` {"tools":[{"name":"calendar.read","inputSchema":{"type":"object"}}]}`)),
	)
	rightSnapshot, err := ParseDefinition(definitionEndpoint, right)
	if err != nil {
		t.Fatal(err)
	}
	if leftDigest == rightSnapshot.Receipt().Digest() {
		t.Fatal("receipt did not distinguish the same concatenated bytes at different page boundaries")
	}
}

func TestParseDefinitionRejectsDuplicateToolsAcrossPages(t *testing.T) {
	source := mustToolsListSnapshot(t,
		toolsListPageFixture{body: `{"tools":[{"name":"calendar.read","inputSchema":{"type":"object"}}],"nextCursor":"page-2"}`},
		toolsListPageFixture{requestedCursor: "page-2", body: `{"tools":[{"name":"calendar.read","inputSchema":{"type":"object"}}]}`},
	)
	_, err := ParseDefinition(definitionEndpoint, source)
	assertDefinitionError(t, err, r3.DefinitionIdentityAmbiguous)
}

func TestParseDefinitionRejectsIncompletePagination(t *testing.T) {
	tests := []struct {
		name  string
		pages []toolsListPageFixture
	}{
		{name: "no pages"},
		{name: "nonfinal page has no next cursor", pages: []toolsListPageFixture{
			{body: `{"tools":[{"name":"calendar.read","inputSchema":{"type":"object"}}]}`},
			{requestedCursor: "page-2", body: `{"tools":[{"name":"calendar.write","inputSchema":{"type":"object"}}]}`},
		}},
		{name: "final page has next cursor", pages: []toolsListPageFixture{
			{body: `{"tools":[{"name":"calendar.read","inputSchema":{"type":"object"}}],"nextCursor":"page-2"}`},
		}},
		{name: "first page has a requested cursor", pages: []toolsListPageFixture{
			{continued: true, requestedCursor: "page-1", body: `{"tools":[{"name":"calendar.read","inputSchema":{"type":"object"}}]}`},
		}},
		{name: "continuation omits requested cursor", pages: []toolsListPageFixture{
			{body: `{"tools":[],"nextCursor":"page-2"}`},
			{body: `{"tools":[{"name":"calendar.read","inputSchema":{"type":"object"}}]}`},
		}},
		{name: "continuation requests empty cursor", pages: []toolsListPageFixture{
			{body: `{"tools":[],"nextCursor":"page-2"}`},
			{continued: true, body: `{"tools":[{"name":"calendar.read","inputSchema":{"type":"object"}}]}`},
		}},
		{name: "continuation requests another cursor", pages: []toolsListPageFixture{
			{body: `{"tools":[],"nextCursor":"page-2"}`},
			{continued: true, requestedCursor: "page-3", body: `{"tools":[{"name":"calendar.read","inputSchema":{"type":"object"}}]}`},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := mustToolsListSnapshot(t, test.pages...)
			_, err := ParseDefinition(definitionEndpoint, source)
			assertDefinitionError(t, err, r3.DefinitionIncompleteSource)
		})
	}
}

func TestParseDefinitionRejectsInvalidAnnotations(t *testing.T) {
	tests := []string{
		`{"tools":[{"name":"calendar.read","inputSchema":{"type":"object"},"_meta":{"aauth.dev/access-mode":"session-token"}}]}`,
		`{"tools":[{"name":"calendar.read","inputSchema":{"type":"object"},"_meta":{"aauth.dev/access-mode":true}}]}`,
		`{"tools":[{"name":"calendar.read","inputSchema":{"type":"object"},"_meta":{"aauth.dev/budget":"yes"}}]}`,
		`{"tools":[{"name":"calendar.read","inputSchema":{"type":"object"},"_meta":{"aauth.dev/budget":null}}]}`,
	}
	for _, body := range tests {
		_, err := ParseDefinition(definitionEndpoint, mustToolsListSnapshot(t, toolsListPageFixture{body: body}))
		assertDefinitionError(t, err, r3.DefinitionInvalidAnnotation)
	}
}

func TestParseDefinitionRejectsInvalidToolInputSchema(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "missing", body: `{"tools":[{"name":"calendar.read"}]}`},
		{name: "not an object", body: `{"tools":[{"name":"calendar.read","inputSchema":true}]}`},
		{name: "not object rooted", body: `{"tools":[{"name":"calendar.read","inputSchema":{"type":"string"}}]}`},
		{name: "invalid properties shape", body: `{"tools":[{"name":"calendar.read","inputSchema":{"type":"object","properties":[]}}]}`},
		{name: "invalid required shape", body: `{"tools":[{"name":"calendar.read","inputSchema":{"type":"object","required":"account"}}]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseDefinition(definitionEndpoint, mustToolsListSnapshot(t, toolsListPageFixture{body: test.body}))
			assertDefinitionError(t, err, r3.DefinitionInvalidSource)
		})
	}
}

func TestParseDefinitionClassifiesExternalInputSchemaReference(t *testing.T) {
	body := `{"tools":[{"name":"calendar.read","inputSchema":{"type":"object","properties":{"record":{"$ref":"https://schemas.example/record.json"}}}}]}`
	_, err := ParseDefinition(
		definitionEndpoint,
		mustToolsListSnapshot(t, toolsListPageFixture{body: body}),
	)
	assertDefinitionError(t, err, r3.DefinitionUnresolvedDependency)
}

func TestDefinitionValidatesKnownOperationsWithoutAddingAuthority(t *testing.T) {
	snapshot, err := ParseDefinition(definitionEndpoint, mustToolsListSnapshot(t,
		toolsListPageFixture{body: `{"tools":[{"name":"calendar.read","inputSchema":{"type":"object"}},{"name":"calendar.write","inputSchema":{"type":"object"}}]}`},
	))
	if err != nil {
		t.Fatal(err)
	}
	known, err := NewOperationSet(mustTypedDefinitionOperation(t, "calendar.read"))
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshot.ValidateDefined(known); err != nil {
		t.Fatalf("ValidateDefined(known) = %v", err)
	}
	unknown, err := NewOperationSet(mustTypedDefinitionOperation(t, "calendar.delete"))
	if err != nil {
		t.Fatal(err)
	}
	err = snapshot.ValidateDefined(unknown)
	assertDefinitionError(t, err, r3.DefinitionOperationNotDefined)

	registry, err := r3.NewDefinitionRegistry(DefinitionRegistration())
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Validate(snapshot); err != nil {
		t.Fatalf("definition registry refused package snapshot: %v", err)
	}
}

func TestDefinitionRetainsNoHintsWhenMetaHasNoR3Annotations(t *testing.T) {
	snapshot, err := ParseDefinition(definitionEndpoint, mustToolsListSnapshot(t,
		toolsListPageFixture{body: `{"tools":[{"name":"calendar.read","inputSchema":{"type":"object"},"_meta":{"vendor.example/color":"blue"}},{"name":"calendar.write","inputSchema":{"type":"object"}}]}`},
	))
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"calendar.read", "calendar.write"} {
		if _, present, err := snapshot.HintsFor(mustDefinitionOperation(t, tool)); err != nil || present {
			t.Fatalf("HintsFor(%q) present = %v, err = %v", tool, present, err)
		}
	}
}

type toolsListPageFixture struct {
	continued       bool
	requestedCursor string
	body            string
}

func mustToolsListSnapshot(t *testing.T, fixtures ...toolsListPageFixture) ToolsListSnapshot {
	t.Helper()
	pages := make([]ToolsListPage, len(fixtures))
	for index, fixture := range fixtures {
		if !fixture.continued && fixture.requestedCursor == "" {
			pages[index] = NewInitialToolsListPage([]byte(fixture.body))
		} else {
			pages[index] = NewContinuedToolsListPage(fixture.requestedCursor, []byte(fixture.body))
		}
	}
	return NewToolsListSnapshot(pages...)
}

func mustTypedDefinitionOperation(t *testing.T, tool string) Operation {
	t.Helper()
	operation, err := NewOperation(tool)
	if err != nil {
		t.Fatal(err)
	}
	return operation
}

func mustDefinitionOperation(t *testing.T, tool string) r3.Operation {
	t.Helper()
	operation, err := mustTypedDefinitionOperation(t, tool).ToR3()
	if err != nil {
		t.Fatal(err)
	}
	return operation
}

func assertDefinitionError(t *testing.T, err error, kind r3.DefinitionErrorKind) {
	t.Helper()
	var typed *r3.DefinitionError
	if !errors.As(err, &typed) {
		t.Fatalf("error = %v, want *r3.DefinitionError", err)
	}
	if typed.Kind != kind {
		t.Fatalf("definition error kind = %q, want %q: %v", typed.Kind, kind, err)
	}
	if typed.Vocabulary != URI {
		t.Fatalf("definition error vocabulary = %q, want %q", typed.Vocabulary, URI)
	}
}
