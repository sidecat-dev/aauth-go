package mcp

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v6"
	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/internal/wirejson"
)

// ToolsListSnapshot is one complete, ordered sequence of exact JSON-encoded
// MCP tools/list result objects. JSON-RPC envelopes are removed by the caller.
// It performs no discovery or transport work.
type ToolsListSnapshot struct {
	pages []ToolsListPage
}

// ToolsListPage binds one requested pagination cursor to the exact JSON-encoded
// result object returned for that request. The initial page has no cursor.
type ToolsListPage struct {
	requestedCursor *string
	resultJSON      []byte
}

// NewInitialToolsListPage copies the exact result object returned by the
// cursor-free initial tools/list request. Pass the JSON value inside the
// JSON-RPC result member, not the complete JSON-RPC response.
func NewInitialToolsListPage(resultJSON []byte) ToolsListPage {
	return ToolsListPage{resultJSON: append([]byte(nil), resultJSON...)}
}

// NewContinuedToolsListPage copies the requested cursor and exact result object
// returned by one tools/list continuation request. Pass the JSON value inside
// the JSON-RPC result member, not the complete response.
func NewContinuedToolsListPage(requestedCursor string, resultJSON []byte) ToolsListPage {
	cursor := requestedCursor
	return ToolsListPage{
		requestedCursor: &cursor,
		resultJSON:      append([]byte(nil), resultJSON...),
	}
}

// NewToolsListSnapshot owns the exact cursor-and-result frame for every page.
// ParseDefinition verifies that each request cursor is the prior response's
// nextCursor and that the sequence is complete.
func NewToolsListSnapshot(pages ...ToolsListPage) ToolsListSnapshot {
	owned := make([]ToolsListPage, len(pages))
	for index, page := range pages {
		owned[index].resultJSON = append([]byte(nil), page.resultJSON...)
		if page.requestedCursor != nil {
			cursor := *page.requestedCursor
			owned[index].requestedCursor = &cursor
		}
	}
	return ToolsListSnapshot{pages: owned}
}

// ToolsListSourceEncoding identifies the reproducible receipt framing used by
// ReceiptInput and SourceReceipt. The encoding is:
//
//   - the UTF-8 prefix "aauth-r3-mcp-tools-list-cursor-result-json-frames" and
//     one zero byte;
//   - the page count as one unsigned 64-bit big-endian integer;
//   - for each page, one cursor-presence byte; when present, the cursor byte
//     length as uint64 followed by its UTF-8 bytes; then the result JSON byte
//     length as uint64 followed by the exact result JSON bytes.
const ToolsListSourceEncoding r3.SourceEncoding = "urn:aauth:source-encoding:mcp-tools-list-cursor-result-json-frames-v1"

// ReceiptInput returns a new copy of the exact framed bytes covered by the
// parsed definition's SourceReceipt. ParseDefinition separately validates the
// cursor chain and each result object before publishing a receipt.
func (source ToolsListSnapshot) ReceiptInput() []byte {
	var framed bytes.Buffer
	framed.WriteString("aauth-r3-mcp-tools-list-cursor-result-json-frames\x00")
	writeUint64(&framed, uint64(len(source.pages)))
	for _, page := range source.pages {
		writeCursorFrame(&framed, page)
	}
	return framed.Bytes()
}

type definitionCodec struct{}

func (definitionCodec) Vocabulary() r3.Vocabulary { return Vocabulary() }

func (definitionCodec) ParseDefinition(source ToolsListSnapshot) (r3.DefinitionMaterial, error) {
	if len(source.pages) == 0 {
		return r3.DefinitionMaterial{}, r3.NewDefinitionError(
			r3.DefinitionIncompleteSource,
			"MCP tools/list snapshot contains no pages",
			nil,
		)
	}

	// Length framing makes the receipt cover page boundaries, requested cursor
	// presence and value, and the exact result object returned for that request.
	receiptInput := source.ReceiptInput()
	defined := make([]r3.DefinedOperation, 0)
	seenTools := make(map[string]struct{})
	seenCursors := make(map[string]struct{})
	var expectedCursor *string
	for pageIndex, frame := range source.pages {
		if pageIndex == 0 {
			if frame.requestedCursor != nil {
				return r3.DefinitionMaterial{}, r3.NewDefinitionError(
					r3.DefinitionIncompleteSource,
					"initial MCP tools/list page must not have a requested cursor",
					nil,
				)
			}
		} else if frame.requestedCursor == nil || expectedCursor == nil || *frame.requestedCursor != *expectedCursor {
			return r3.DefinitionMaterial{}, r3.NewDefinitionError(
				r3.DefinitionIncompleteSource,
				fmt.Sprintf("MCP tools/list page %d was not requested with prior nextCursor", pageIndex),
				nil,
			)
		}
		if err := wirejson.ValidateSource(frame.resultJSON); err != nil {
			return r3.DefinitionMaterial{}, r3.NewDefinitionError(
				r3.DefinitionInvalidSource,
				fmt.Sprintf("invalid MCP tools/list page %d", pageIndex),
				err,
			)
		}
		page, err := parseToolsListPage(frame.resultJSON)
		if err != nil {
			var typed *r3.DefinitionError
			if errors.As(err, &typed) {
				return r3.DefinitionMaterial{}, err
			}
			return r3.DefinitionMaterial{}, r3.NewDefinitionError(
				r3.DefinitionInvalidSource,
				fmt.Sprintf("invalid MCP tools/list page %d", pageIndex),
				err,
			)
		}
		final := pageIndex == len(source.pages)-1
		if final && page.nextCursor != nil {
			return r3.DefinitionMaterial{}, r3.NewDefinitionError(
				r3.DefinitionIncompleteSource,
				fmt.Sprintf("final MCP tools/list page %d advertises another page", pageIndex),
				nil,
			)
		}
		if !final {
			if page.nextCursor == nil || *page.nextCursor == "" {
				return r3.DefinitionMaterial{}, r3.NewDefinitionError(
					r3.DefinitionIncompleteSource,
					fmt.Sprintf("MCP tools/list page %d does not identify the next page", pageIndex),
					nil,
				)
			}
			if _, duplicate := seenCursors[*page.nextCursor]; duplicate {
				return r3.DefinitionMaterial{}, r3.NewDefinitionError(
					r3.DefinitionIncompleteSource,
					fmt.Sprintf("MCP tools/list page %d repeats nextCursor %q", pageIndex, *page.nextCursor),
					nil,
				)
			}
			seenCursors[*page.nextCursor] = struct{}{}
		}
		expectedCursor = page.nextCursor
		for _, tool := range page.tools {
			if _, duplicate := seenTools[tool.operation.Tool()]; duplicate {
				return r3.DefinitionMaterial{}, r3.NewDefinitionError(
					r3.DefinitionIdentityAmbiguous,
					fmt.Sprintf("MCP tool %q occurs more than once", tool.operation.Tool()),
					nil,
				)
			}
			seenTools[tool.operation.Tool()] = struct{}{}
			encoded, err := json.Marshal(tool.operation)
			if err != nil {
				return r3.DefinitionMaterial{}, r3.NewDefinitionError(r3.DefinitionInvalidSource, "encode derived MCP tool", err)
			}
			var hints *r3.OperationHints
			if tool.hintsPresent {
				hints = &tool.hints
			}
			operation, err := r3.NewDefinedOperation(encoded, hints)
			if err != nil {
				return r3.DefinitionMaterial{}, r3.NewDefinitionError(r3.DefinitionInvalidSource, "construct derived MCP tool", err)
			}
			defined = append(defined, operation)
		}
	}
	if len(defined) == 0 {
		return r3.DefinitionMaterial{}, r3.NewDefinitionError(r3.DefinitionIncompleteSource, "MCP tools/list snapshot defines no tools", nil)
	}
	return r3.NewDefinitionMaterial(ToolsListSourceEncoding, receiptInput, defined...)
}

var definitionParser = mustDefinitionParser()

func mustDefinitionParser() r3.DefinitionParser[ToolsListSnapshot] {
	parser, err := r3.NewDefinitionParser(definitionCodec{})
	if err != nil {
		panic(err)
	}
	return parser
}

// ParseDefinition derives an authoritative MCP snapshot from already-acquired
// tools/list pages. It never performs network or MCP transport I/O.
func ParseDefinition(endpoint string, source ToolsListSnapshot) (r3.AuthoritativeSnapshot, error) {
	return definitionParser.Parse(endpoint, source)
}

// DefinitionRegistration returns the MCP parser identity for an explicit
// r3.DefinitionRegistry allowlist.
func DefinitionRegistration() r3.DefinitionRegistration {
	return definitionParser.Registration()
}

type toolsListPage struct {
	tools      []definedTool
	nextCursor *string
}

type definedTool struct {
	operation    Operation
	hints        r3.OperationHints
	hintsPresent bool
}

func parseToolsListPage(body []byte) (toolsListPage, error) {
	var wire struct {
		Tools      json.RawMessage `json:"tools"`
		NextCursor json.RawMessage `json:"nextCursor"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return toolsListPage{}, err
	}
	if len(wire.Tools) == 0 {
		return toolsListPage{}, errors.New("MCP tools/list page is missing tools")
	}
	if trimmed := bytes.TrimSpace(wire.Tools); len(trimmed) == 0 || trimmed[0] != '[' {
		return toolsListPage{}, errors.New("MCP tools/list tools must be an array")
	}
	var toolValues []json.RawMessage
	if err := json.Unmarshal(wire.Tools, &toolValues); err != nil {
		return toolsListPage{}, fmt.Errorf("MCP tools/list tools: %w", err)
	}
	page := toolsListPage{tools: make([]definedTool, len(toolValues))}
	for index, raw := range toolValues {
		tool, err := parseDefinedTool(raw)
		if err != nil {
			return toolsListPage{}, fmt.Errorf("MCP tools/list tool %d: %w", index, err)
		}
		page.tools[index] = tool
	}
	if len(wire.NextCursor) != 0 {
		var cursor string
		if err := json.Unmarshal(wire.NextCursor, &cursor); err != nil {
			return toolsListPage{}, fmt.Errorf("MCP tools/list nextCursor: %w", err)
		}
		page.nextCursor = &cursor
	}
	return page, nil
}

func parseDefinedTool(raw []byte) (definedTool, error) {
	var wire struct {
		Name        json.RawMessage `json:"name"`
		InputSchema json.RawMessage `json:"inputSchema"`
		Meta        json.RawMessage `json:"_meta"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return definedTool{}, err
	}
	if len(wire.Name) == 0 {
		return definedTool{}, errors.New("MCP tool is missing name")
	}
	var name string
	if err := json.Unmarshal(wire.Name, &name); err != nil {
		return definedTool{}, fmt.Errorf("MCP tool name: %w", err)
	}
	operation, err := NewOperation(name)
	if err != nil {
		return definedTool{}, err
	}
	if err := validateInputSchema(wire.InputSchema); err != nil {
		return definedTool{}, err
	}
	tool := definedTool{operation: operation}
	if len(wire.Meta) != 0 {
		hints, hintsPresent, err := parseMetaHints(wire.Meta)
		if err != nil {
			return definedTool{}, err
		}
		tool.hints = hints
		tool.hintsPresent = hintsPresent
	}
	return tool, nil
}

func parseMetaHints(raw []byte) (r3.OperationHints, bool, error) {
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || trimmed[0] != '{' {
		return r3.OperationHints{}, false, r3.NewDefinitionError(
			r3.DefinitionInvalidAnnotation,
			"MCP tool _meta must be an object",
			nil,
		)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return r3.OperationHints{}, false, invalidAnnotation("MCP tool _meta must be an object", err)
	}
	var accessMode *aauth.AccessMode
	if value, present := fields["aauth.dev/access-mode"]; present {
		var decoded aauth.AccessMode
		if err := json.Unmarshal(value, &decoded); err != nil {
			return r3.OperationHints{}, false, invalidAnnotation("MCP access-mode must be a string", err)
		}
		accessMode = &decoded
	}
	var budget *bool
	if value, present := fields["aauth.dev/budget"]; present {
		var decoded *bool
		if err := json.Unmarshal(value, &decoded); err != nil || decoded == nil {
			return r3.OperationHints{}, false, invalidAnnotation("MCP budget must be a boolean", err)
		}
		budget = decoded
	}
	if accessMode == nil && budget == nil {
		return r3.OperationHints{}, false, nil
	}
	hints, err := r3.NewOperationHints(accessMode, budget)
	if err != nil {
		return r3.OperationHints{}, false, invalidAnnotation("invalid MCP operation hints", err)
	}
	return hints, true, nil
}

func invalidAnnotation(reason string, cause error) error {
	return r3.NewDefinitionError(r3.DefinitionInvalidAnnotation, reason, cause)
}

type noExternalSchemaLoader struct{ requested *string }

func (loader noExternalSchemaLoader) Load(url string) (any, error) {
	*loader.requested = url
	return nil, fmt.Errorf("external MCP input schema reference: %s", url)
}

func validateInputSchema(raw json.RawMessage) error {
	if len(raw) == 0 {
		return r3.NewDefinitionError(r3.DefinitionInvalidSource, "MCP tool is missing inputSchema", nil)
	}
	decoded, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return r3.NewDefinitionError(r3.DefinitionInvalidSource, "MCP tool inputSchema is invalid JSON", err)
	}
	object, ok := decoded.(map[string]any)
	if !ok {
		return r3.NewDefinitionError(r3.DefinitionInvalidSource, "MCP tool inputSchema must be a JSON Schema object", nil)
	}
	if object["type"] != "object" {
		return r3.NewDefinitionError(r3.DefinitionInvalidSource, "MCP tool inputSchema must have object root type", nil)
	}
	compiler := jsonschema.NewCompiler()
	var externalReference string
	compiler.UseLoader(noExternalSchemaLoader{requested: &externalReference})
	const location = "urn:aauth:mcp:tool-input-schema"
	if err := compiler.AddResource(location, decoded); err != nil {
		return r3.NewDefinitionError(r3.DefinitionInvalidSource, "register MCP tool inputSchema", err)
	}
	if _, err := compiler.Compile(location); err != nil {
		if externalReference != "" {
			return r3.NewDefinitionError(r3.DefinitionUnresolvedDependency, "MCP tool inputSchema requires external reference resolution", err)
		}
		return r3.NewDefinitionError(r3.DefinitionInvalidSource, "MCP tool inputSchema is not a valid JSON Schema", err)
	}
	return nil
}

func writeCursorFrame(target *bytes.Buffer, page ToolsListPage) {
	if page.requestedCursor == nil {
		target.WriteByte(0)
	} else {
		target.WriteByte(1)
		writeUint64(target, uint64(len(*page.requestedCursor)))
		target.WriteString(*page.requestedCursor)
	}
	writeUint64(target, uint64(len(page.resultJSON)))
	target.Write(page.resultJSON)
}

func writeUint64(target *bytes.Buffer, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	target.Write(encoded[:])
}
