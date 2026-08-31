package vocabtest_test

import (
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/asyncapi"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/graphql"
	grpcvocab "gitlab.com/sidecat-dev/aauth-go/r3/vocab/grpc"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/odata"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/openapi"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/wsdl"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocabtest"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestDefinitionContractExercisesNativeMCPSource(t *testing.T) {
	source := mcp.NewToolsListSnapshot(mcp.NewInitialToolsListPage([]byte(`{"tools":[{"name":"read","inputSchema":{"type":"object"},"_meta":{"aauth.dev/access-mode":"person-token","aauth.dev/budget":false}}]}`)))
	changed := mcp.NewToolsListSnapshot(mcp.NewInitialToolsListPage([]byte(`{"tools":[{"name":"read","inputSchema":{"type":"object"},"_meta":{"aauth.dev/access-mode":"person-token","aauth.dev/budget":false}},{"name":"write","inputSchema":{"type":"object"}}]}`)))
	invalid := mcp.NewToolsListSnapshot(mcp.NewInitialToolsListPage([]byte(`{"tools":[{"name":"read","inputSchema":{"type":"object"},"_meta":{"aauth.dev/budget":"yes"}}]}`)))
	mode := aauth.AccessModePersonToken
	budget := false
	known := mustMCPContractOperation(t, "read")
	vocabtest.RunDefinition(t, vocabtest.DefinitionContract[mcp.ToolsListSnapshot]{
		Registration:  mcp.DefinitionRegistration(),
		Parse:         mcp.ParseDefinition,
		Endpoint:      "https://resource.example/mcp",
		Source:        source,
		ChangedSource: changed,
		Known:         known,
		Unknown:       mustMCPContractOperation(t, "unknown"),
		ChangedOnly:   mustMCPContractOperation(t, "write"),
		Hints: &vocabtest.DefinitionHintsExpectation{
			Operation: known, AccessMode: &mode, Budget: &budget,
		},
		Refusals: []vocabtest.DefinitionRefusal[mcp.ToolsListSnapshot]{
			{Name: "invalid annotation", Source: invalid, Kind: r3.DefinitionInvalidAnnotation},
		},
	})
}

func TestDefinitionContractExercisesAsyncAPIDocument(t *testing.T) {
	vocabtest.RunDefinition(t, vocabtest.DefinitionContract[asyncapi.JSONDocumentSource]{
		Registration: asyncapi.DefinitionRegistration(),
		Parse:        asyncapi.ParseDefinition,
		Endpoint:     "https://resource.example/asyncapi.json",
		Source: asyncapi.NewJSONDocumentSource(
			[]byte(asyncAPIContractSource(`"read":{"action":"receive","channel":{"$ref":"#/channels/events"}}`)),
		),
		ChangedSource: asyncapi.NewJSONDocumentSource(
			[]byte(asyncAPIContractSource(`"read":{"action":"receive","channel":{"$ref":"#/channels/events"}},"write":{"action":"send","channel":{"$ref":"#/channels/events"}}`)),
		),
		Known:       mustAsyncAPIContractOperation(t, "read", asyncapi.ActionReceive),
		Unknown:     mustAsyncAPIContractOperation(t, "unknown", asyncapi.ActionReceive),
		ChangedOnly: mustAsyncAPIContractOperation(t, "write", asyncapi.ActionSend),
		Refusals: []vocabtest.DefinitionRefusal[asyncapi.JSONDocumentSource]{
			{Name: "missing action", Source: asyncapi.NewJSONDocumentSource([]byte(asyncAPIContractSource(`"read":{"channel":{"$ref":"#/channels/events"}}`))), Kind: r3.DefinitionInvalidSource},
		},
	})
}

func TestDefinitionContractExercisesOpenAPIDocument(t *testing.T) {
	vocabtest.RunDefinition(t, vocabtest.DefinitionContract[openapi.DocumentSource]{
		Registration: openapi.DefinitionRegistration(),
		Parse:        openapi.ParseDefinition,
		Endpoint:     "https://resource.example/openapi.json",
		Source: openapi.NewDocumentSource([]byte(
			`{"openapi":"3.1.0","info":{"title":"test","version":"1"},"paths":{"/read":{"get":{"operationId":"read","responses":{"204":{"description":"ok"}}}}}}`,
		)),
		ChangedSource: openapi.NewDocumentSource([]byte(
			`{"openapi":"3.1.0","info":{"title":"test","version":"1"},"paths":{"/read":{"get":{"operationId":"read","responses":{"204":{"description":"ok"}}}},"/write":{"post":{"operationId":"write","responses":{"204":{"description":"ok"}}}}}}`,
		)),
		Known:       mustOpenAPIContractOperation(t, "read"),
		Unknown:     mustOpenAPIContractOperation(t, "unknown"),
		ChangedOnly: mustOpenAPIContractOperation(t, "write"),
		Refusals: []vocabtest.DefinitionRefusal[openapi.DocumentSource]{
			{Name: "unsupported version", Source: openapi.NewDocumentSource([]byte(`{"swagger":"2.0"}`)), Kind: r3.DefinitionSourceKindUnsupported},
		},
	})
}

func TestDefinitionContractExercisesGRPCDescriptorSet(t *testing.T) {
	vocabtest.RunDefinition(t, vocabtest.DefinitionContract[grpcvocab.DefinitionSource]{
		Registration:  grpcvocab.DefinitionRegistration(),
		Parse:         grpcvocab.ParseDefinition,
		Endpoint:      "https://resource.example/grpc-descriptors",
		Source:        grpcvocab.NewDescriptorSetSource(grpcContractSource(t, "Read")),
		ChangedSource: grpcvocab.NewDescriptorSetSource(grpcContractSource(t, "Read", "Write")),
		Known:         mustGRPCContractOperation(t, "example.records.Records/Read"),
		Unknown:       mustGRPCContractOperation(t, "example.records.Records/Unknown"),
		ChangedOnly:   mustGRPCContractOperation(t, "example.records.Records/Write"),
		Refusals: []vocabtest.DefinitionRefusal[grpcvocab.DefinitionSource]{
			{Name: "hosted source requires acquisition", Source: grpcvocab.NewHostedProtoTextSource([]byte(`syntax = "proto3";`)), Kind: r3.DefinitionSourceKindUnsupported},
		},
	})
}

func TestDefinitionContractExercisesWSDLDocument(t *testing.T) {
	vocabtest.RunDefinition(t, vocabtest.DefinitionContract[wsdl.XMLDocumentSource]{
		Registration:  wsdl.DefinitionRegistration(),
		Parse:         wsdl.ParseDefinition,
		Endpoint:      "https://resource.example/service.wsdl",
		Source:        wsdl.NewXMLDocumentSource([]byte(wsdlContractSource("<operation name=\"Read\"><input message=\"tns:ReadRequest\"/></operation>", "<operation name=\"Read\"/>"))),
		ChangedSource: wsdl.NewXMLDocumentSource([]byte(wsdlContractSource("<operation name=\"Read\"><input message=\"tns:ReadRequest\"/></operation><operation name=\"Write\"><input message=\"tns:WriteRequest\"/></operation>", "<operation name=\"Read\"/><operation name=\"Write\"/>"))),
		Known:         mustWSDLContractOperation(t, "Read"),
		Unknown:       mustWSDLContractOperation(t, "Unknown"),
		ChangedOnly:   mustWSDLContractOperation(t, "Write"),
		Refusals: []vocabtest.DefinitionRefusal[wsdl.XMLDocumentSource]{
			{Name: "unresolved import", Source: wsdl.NewXMLDocumentSource([]byte(`<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" targetNamespace="urn:test"><import location="other.wsdl"/></definitions>`)), Kind: r3.DefinitionUnresolvedDependency},
		},
	})
}

func TestDefinitionContractExercisesODataMetadata(t *testing.T) {
	vocabtest.RunDefinition(t, vocabtest.DefinitionContract[odata.MetadataSource]{
		Registration:  odata.DefinitionRegistration(),
		Parse:         odata.ParseDefinition,
		Endpoint:      "https://resource.example/odata",
		Source:        odata.NewMetadataSource([]byte(odataContractSource(`<EntitySet Name="Events" EntityType="Calendar.Event"/>`))),
		ChangedSource: odata.NewMetadataSource([]byte(odataContractSource(`<EntitySet Name="Events" EntityType="Calendar.Event"/><EntitySet Name="Archive" EntityType="Calendar.Event"/>`))),
		Known:         mustODataContractOperation(t, "Events"),
		Unknown:       mustODataContractOperation(t, "Unknown"),
		ChangedOnly:   mustODataContractOperation(t, "Archive"),
		Refusals: []vocabtest.DefinitionRefusal[odata.MetadataSource]{
			{Name: "unresolved reference", Source: odata.NewMetadataSource([]byte(`<edmx:Edmx xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx" Version="4.0"><edmx:Reference Uri="other.xml"/><edmx:DataServices/></edmx:Edmx>`)), Kind: r3.DefinitionUnresolvedDependency},
		},
	})
}

func TestDefinitionRefusalContractExercisesGraphQLIdentityGap(t *testing.T) {
	vocabtest.RunDefinitionRefusal(t, vocabtest.DefinitionRefusalContract[graphql.IntrospectionSource]{
		Parse:      graphql.ParseDefinition,
		Endpoint:   "https://resource.example/graphql",
		Vocabulary: graphql.URI,
		Source: graphql.NewIntrospectionSource(
			[]byte(`{"data":{"__schema":{"queryType":{"name":"Query"}}}}`),
		),
		Kind: r3.DefinitionIdentityUnavailable,
	})
}

func mustMCPContractOperation(t *testing.T, name string) r3.Operation {
	t.Helper()
	operation, err := mcp.NewOperation(name)
	if err != nil {
		t.Fatal(err)
	}
	neutral, err := operation.ToR3()
	if err != nil {
		t.Fatal(err)
	}
	return neutral
}

func mustAsyncAPIContractOperation(t *testing.T, name string, action asyncapi.Action) r3.Operation {
	t.Helper()
	operation, err := asyncapi.NewOperationWithAction(name, action)
	if err != nil {
		t.Fatal(err)
	}
	neutral, err := operation.ToR3()
	if err != nil {
		t.Fatal(err)
	}
	return neutral
}

func mustOpenAPIContractOperation(t *testing.T, name string) r3.Operation {
	t.Helper()
	operation, err := openapi.NewOperation(name)
	if err != nil {
		t.Fatal(err)
	}
	neutral, err := operation.ToR3()
	if err != nil {
		t.Fatal(err)
	}
	return neutral
}

func mustGRPCContractOperation(t *testing.T, method string) r3.Operation {
	t.Helper()
	operation, err := grpcvocab.NewOperation(method)
	if err != nil {
		t.Fatal(err)
	}
	neutral, err := operation.ToR3()
	if err != nil {
		t.Fatal(err)
	}
	return neutral
}

func mustWSDLContractOperation(t *testing.T, name string) r3.Operation {
	t.Helper()
	operation, err := wsdl.NewOperation(name)
	if err != nil {
		t.Fatal(err)
	}
	neutral, err := operation.ToR3()
	if err != nil {
		t.Fatal(err)
	}
	return neutral
}

func mustODataContractOperation(t *testing.T, name string) r3.Operation {
	t.Helper()
	operation, err := odata.NewOperation(name)
	if err != nil {
		t.Fatal(err)
	}
	neutral, err := operation.ToR3()
	if err != nil {
		t.Fatal(err)
	}
	return neutral
}

func wsdlContractSource(portTypeOperations, bindingOperations string) string {
	return `<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:tns="urn:test" targetNamespace="urn:test"><message name="ReadRequest"/><message name="WriteRequest"/><portType name="Port">` + portTypeOperations + `</portType><binding name="Binding" type="tns:Port">` + bindingOperations + `</binding><service name="Service"><port name="Port" binding="tns:Binding"/></service></definitions>`
}

func odataContractSource(entitySets string) string {
	return `<edmx:Edmx xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx" Version="4.0"><edmx:DataServices><Schema xmlns="http://docs.oasis-open.org/odata/ns/edm" Namespace="Calendar"><EntityType Name="Event"/><EntityContainer Name="Service">` + entitySets + `</EntityContainer></Schema></edmx:DataServices></edmx:Edmx>`
}

func asyncAPIContractSource(operations string) string {
	return `{"asyncapi":"3.0.0","info":{"title":"events","version":"1"},"channels":{"events":{"address":"events","messages":{}}},"operations":{` + operations + `}}`
}

func grpcContractSource(t *testing.T, methods ...string) []byte {
	t.Helper()
	descriptors := make([]*descriptorpb.MethodDescriptorProto, len(methods))
	for index, method := range methods {
		descriptors[index] = &descriptorpb.MethodDescriptorProto{
			Name:       proto.String(method),
			InputType:  proto.String(".example.records.Request"),
			OutputType: proto.String(".example.records.Response"),
		}
	}
	set := &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{{
		Name:    proto.String("records.proto"),
		Package: proto.String("example.records"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: proto.String("Request")},
			{Name: proto.String("Response")},
		},
		Service: []*descriptorpb.ServiceDescriptorProto{{Name: proto.String("Records"), Method: descriptors}},
	}}}
	exact, err := proto.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	return exact
}
