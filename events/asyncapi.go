package events

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
	"gitlab.com/sidecat-dev/aauth-go/r3"
)

const maximumEventsAsyncAPIDocument = 1 << 20

var eventsChannelExpression = regexp.MustCompile(`\{([A-Za-z0-9_-]+)\}`)

// EventsAsyncAPIContract is the immutable, exact-byte identity of the narrow
// AsyncAPI 3.0.0 profile selected by AAuth Events M6. It deliberately models
// one protected channel, operation, and JSON message rather than claiming to
// be a general AsyncAPI parser.
type EventsAsyncAPIContract struct {
	exact   []byte
	digest  string
	message EventsAsyncAPIMessage
}

// EventsAsyncAPIMessage is one exact protected operation/message selection.
// ValidatePayload applies the schema compiled from the retained contract
// without network access or source reserialization.
type EventsAsyncAPIMessage struct {
	OperationID     string
	ChannelID       string
	MessageID       string
	Address         string
	TicketParameter string
	ContentType     string

	schema *jsonschema.Schema
}

// Digest returns the unpadded base64url SHA-256 identity of the exact document.
func (contract *EventsAsyncAPIContract) Digest() string {
	if contract == nil {
		return ""
	}
	return contract.digest
}

// ExactBytes returns an independent copy of the exact parsed document.
func (contract *EventsAsyncAPIContract) ExactBytes() []byte {
	if contract == nil {
		return nil
	}
	return append([]byte(nil), contract.exact...)
}

// ProtectedMessage selects the one operation/message pair admitted by this
// narrow contract. Exact identifiers are required so ticket records can bind
// the same selection across process replacement.
func (contract *EventsAsyncAPIContract) ProtectedMessage(
	operationID string,
	messageID string,
) (EventsAsyncAPIMessage, error) {
	if contract == nil || operationID == "" || messageID == "" ||
		contract.message.schema == nil {
		return EventsAsyncAPIMessage{}, errors.New("aauth: Events AsyncAPI selection is invalid")
	}
	if operationID != contract.message.OperationID || messageID != contract.message.MessageID {
		return EventsAsyncAPIMessage{}, errors.New("aauth: Events AsyncAPI selection was not found")
	}
	return contract.message, nil
}

// ValidatePayload validates one complete direct JSON event body. A second JSON
// value, duplicate object name, or empty body is rejected before schema use.
func (message EventsAsyncAPIMessage) ValidatePayload(exact []byte) error {
	if message.schema == nil {
		return errors.New("aauth: Events AsyncAPI message is not configured")
	}
	if len(exact) == 0 {
		return errors.New("aauth: Events payload is required")
	}
	if err := jsonstrict.RejectAmbiguousNames(exact); err != nil {
		return fmt.Errorf("aauth: Events payload: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(exact))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return fmt.Errorf("aauth: decode Events payload: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("aauth: Events payload has trailing data")
	}
	if err := message.schema.Validate(value); err != nil {
		return fmt.Errorf("aauth: Events payload does not match AsyncAPI message: %w", err)
	}
	return nil
}

type eventsAsyncAPIDocument struct {
	Version    string                             `json:"asyncapi"`
	Info       eventsAsyncAPIInfo                 `json:"info"`
	Channels   map[string]eventsAsyncAPIChannel   `json:"channels"`
	Operations map[string]eventsAsyncAPIOperation `json:"operations"`
	Components eventsAsyncAPIComponents           `json:"components"`
}

type eventsAsyncAPIInfo struct {
	Title   string `json:"title"`
	Version string `json:"version"`
}

type eventsAsyncAPIChannel struct {
	Address     string                             `json:"address"`
	Description string                             `json:"description"`
	Parameters  map[string]eventsAsyncAPIParameter `json:"parameters"`
	Messages    map[string]eventsAsyncAPIReference `json:"messages"`
}

type eventsAsyncAPIParameter struct {
	Description string `json:"description"`
}

type eventsAsyncAPIReference struct {
	Ref string `json:"$ref"`
}

type eventsAsyncAPIOperation struct {
	Action   string                    `json:"action"`
	Channel  eventsAsyncAPIReference   `json:"channel"`
	Messages []eventsAsyncAPIReference `json:"messages,omitempty"`
	Security json.RawMessage           `json:"security,omitempty"`
}

type eventsAsyncAPIComponents struct {
	Messages        map[string]eventsAsyncAPIMessageDocument `json:"messages"`
	SecuritySchemes map[string]eventsAsyncAPISecurityScheme  `json:"securitySchemes"`
}

type eventsAsyncAPIMessageDocument struct {
	ContentType string          `json:"contentType"`
	Payload     json.RawMessage `json:"payload"`
}

type eventsAsyncAPISecurityScheme struct {
	Type   string `json:"type"`
	Scheme string `json:"scheme"`
}

// ParseEventsAsyncAPI parses the selected one-channel JSON AsyncAPI 3.0.0
// profile and compiles its inline payload schema under JSON Schema Draft 7.
// Message and channel references must be local; payload-schema references are
// excluded from this first exact profile so validation can never trigger I/O.
func ParseEventsAsyncAPI(exact []byte) (*EventsAsyncAPIContract, error) {
	if len(exact) == 0 {
		return nil, errors.New("aauth: Events AsyncAPI document is empty")
	}
	if len(exact) > maximumEventsAsyncAPIDocument {
		return nil, errors.New("aauth: Events AsyncAPI document is too large")
	}
	if err := jsonstrict.RejectAmbiguousNames(exact); err != nil {
		return nil, fmt.Errorf("aauth: Events AsyncAPI document: %w", err)
	}
	var document eventsAsyncAPIDocument
	if err := json.Unmarshal(exact, &document); err != nil {
		return nil, fmt.Errorf("aauth: parse Events AsyncAPI document: %w", err)
	}
	if document.Version != "3.0.0" {
		return nil, errors.New("aauth: Events AsyncAPI version must be 3.0.0")
	}
	if strings.TrimSpace(document.Info.Title) == "" || strings.TrimSpace(document.Info.Version) == "" {
		return nil, errors.New("aauth: Events AsyncAPI info title and version are required")
	}
	if len(document.Channels) != 1 || len(document.Operations) != 1 {
		return nil, errors.New("aauth: Events AsyncAPI profile requires one channel and one operation")
	}
	security, ok := document.Components.SecuritySchemes["aauth_subscribe"]
	if !ok || security.Type != "http" || security.Scheme != "aauth-subscribe" {
		return nil, errors.New("aauth: Events AsyncAPI aauth_subscribe security scheme is invalid")
	}

	operationID, operation := onlyEventsAsyncAPIOperation(document.Operations)
	if operationID == "" || operation.Action != "receive" {
		return nil, errors.New("aauth: Events AsyncAPI protected operation must receive")
	}
	if len(operation.Security) != 0 {
		return nil, errors.New("aauth: Events AsyncAPI protected operation must not declare security")
	}
	channelID, err := localEventsAsyncAPIReference(operation.Channel.Ref, "#/channels/")
	if err != nil {
		return nil, fmt.Errorf("aauth: Events AsyncAPI operation channel: %w", err)
	}
	channel, ok := document.Channels[channelID]
	if !ok || len(channel.Messages) != 1 {
		return nil, errors.New("aauth: Events AsyncAPI operation channel must contain one message")
	}
	if strings.TrimSpace(channel.Description) == "" {
		return nil, errors.New("aauth: Events AsyncAPI protected channel description is required")
	}
	ticketParameter, err := protectedTicketParameter(channel)
	if err != nil {
		return nil, err
	}

	messageID, messageReference := onlyEventsAsyncAPIMessageReference(channel.Messages)
	componentID, err := localEventsAsyncAPIReference(messageReference.Ref, "#/components/messages/")
	if err != nil {
		return nil, fmt.Errorf("aauth: Events AsyncAPI channel message: %w", err)
	}
	if len(operation.Messages) != 0 {
		if len(operation.Messages) != 1 ||
			operation.Messages[0].Ref != "#/channels/"+channelID+"/messages/"+messageID {
			return nil, errors.New("aauth: Events AsyncAPI operation message selection is invalid")
		}
	}
	messageDocument, ok := document.Components.Messages[componentID]
	if !ok || messageDocument.ContentType != "application/json" || len(messageDocument.Payload) == 0 {
		return nil, errors.New("aauth: Events AsyncAPI message must define an application/json payload")
	}
	if containsEventsAsyncAPIReference(messageDocument.Payload) {
		return nil, errors.New("aauth: Events AsyncAPI payload schema references are unsupported")
	}
	compiled, err := compileEventsPayloadSchema(messageDocument.Payload)
	if err != nil {
		return nil, err
	}
	return &EventsAsyncAPIContract{
		exact:  append([]byte(nil), exact...),
		digest: r3.S256(exact),
		message: EventsAsyncAPIMessage{
			OperationID: operationID, ChannelID: channelID, MessageID: messageID,
			Address: channel.Address, TicketParameter: ticketParameter,
			ContentType: messageDocument.ContentType, schema: compiled,
		},
	}, nil
}

func onlyEventsAsyncAPIOperation(
	operations map[string]eventsAsyncAPIOperation,
) (string, eventsAsyncAPIOperation) {
	for identifier, operation := range operations {
		return identifier, operation
	}
	return "", eventsAsyncAPIOperation{}
}

func onlyEventsAsyncAPIMessageReference(
	messages map[string]eventsAsyncAPIReference,
) (string, eventsAsyncAPIReference) {
	for identifier, reference := range messages {
		return identifier, reference
	}
	return "", eventsAsyncAPIReference{}
}

func localEventsAsyncAPIReference(reference string, prefix string) (string, error) {
	if !strings.HasPrefix(reference, prefix) {
		return "", errors.New("reference must be local")
	}
	identifier := strings.TrimPrefix(reference, prefix)
	if identifier == "" || strings.ContainsAny(identifier, "/~") {
		return "", errors.New("reference identifier is invalid")
	}
	return identifier, nil
}

func protectedTicketParameter(channel eventsAsyncAPIChannel) (string, error) {
	matches := eventsChannelExpression.FindAllStringSubmatch(channel.Address, -1)
	if len(matches) != 1 || len(matches[0]) != 2 || matches[0][1] != "subscriptionTicket" ||
		len(channel.Parameters) != 1 {
		return "", errors.New("aauth: Events AsyncAPI protected channel requires one subscriptionTicket expression")
	}
	parameterSegment := "{" + matches[0][1] + "}"
	foundSegment := false
	for _, segment := range strings.Split(channel.Address, "/") {
		if segment == parameterSegment {
			foundSegment = true
			break
		}
	}
	if !foundSegment {
		return "", errors.New("aauth: Events AsyncAPI subscriptionTicket expression must occupy one complete path segment")
	}
	parameter, ok := channel.Parameters[matches[0][1]]
	if !ok || strings.TrimSpace(parameter.Description) == "" {
		return "", errors.New("aauth: Events AsyncAPI subscriptionTicket parameter is invalid")
	}
	return matches[0][1], nil
}

func containsEventsAsyncAPIReference(exact []byte) bool {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(exact))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		return true
	}
	return eventsJSONContainsReference(value)
}

func eventsJSONContainsReference(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for name, child := range typed {
			if name == "$ref" || eventsJSONContainsReference(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if eventsJSONContainsReference(child) {
				return true
			}
		}
	}
	return false
}

func compileEventsPayloadSchema(exact []byte) (*jsonschema.Schema, error) {
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(exact))
	if err != nil {
		return nil, fmt.Errorf("aauth: parse Events AsyncAPI payload schema: %w", err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft7)
	compiler.AssertFormat()
	const location = "urn:aauth:events:payload-schema"
	if err := compiler.AddResource(location, value); err != nil {
		return nil, fmt.Errorf("aauth: add Events AsyncAPI payload schema: %w", err)
	}
	compiled, err := compiler.Compile(location)
	if err != nil {
		return nil, fmt.Errorf("aauth: compile Events AsyncAPI payload schema: %w", err)
	}
	return compiled, nil
}
