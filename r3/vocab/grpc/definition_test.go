package grpc

import (
	"errors"
	"slices"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/r3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

const definitionEndpoint = "https://resource.example/grpc-definition"

func TestParseDefinitionDerivesEveryLinkedMethodDeterministically(t *testing.T) {
	exact := mustMarshalDescriptorSet(t, &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{
		{
			Name:    proto.String("calendar.proto"),
			Package: proto.String("example.calendar"),
			Syntax:  proto.String("proto3"),
			Dependency: []string{
				"common.proto",
			},
			Service: []*descriptorpb.ServiceDescriptorProto{{
				Name: proto.String("Calendar"),
				Method: []*descriptorpb.MethodDescriptorProto{
					{Name: proto.String("Write"), InputType: proto.String(".example.common.Request"), OutputType: proto.String(".example.common.Response")},
					{Name: proto.String("Read"), InputType: proto.String(".example.common.Request"), OutputType: proto.String(".example.common.Response")},
				},
			}},
		},
		{
			Name:    proto.String("common.proto"),
			Package: proto.String("example.common"),
			Syntax:  proto.String("proto3"),
			MessageType: []*descriptorpb.DescriptorProto{
				{Name: proto.String("Request")},
				{Name: proto.String("Response")},
			},
		},
		{
			Name:    proto.String("admin.proto"),
			Package: proto.String("example.admin"),
			Syntax:  proto.String("proto3"),
			Dependency: []string{
				"common.proto",
			},
			Service: []*descriptorpb.ServiceDescriptorProto{{
				Name: proto.String("Admin"),
				Method: []*descriptorpb.MethodDescriptorProto{{
					Name:       proto.String("Ping"),
					InputType:  proto.String(".example.common.Request"),
					OutputType: proto.String(".example.common.Response"),
				}},
			}},
		},
	}})
	owned := slices.Clone(exact)
	source := NewDescriptorSetSource(exact)
	exact[0] ^= 0xff

	snapshot, err := ParseDefinition(definitionEndpoint, source)
	if err != nil {
		t.Fatal(err)
	}
	if got := snapshot.Vocabulary(); got != URI {
		t.Fatalf("Vocabulary() = %q, want %q", got, URI)
	}
	if got := snapshot.Receipt().Digest(); got != r3.Digest(owned) {
		t.Fatalf("source digest = %q, want digest of exact descriptor bytes", got)
	}
	if got := snapshot.Receipt().ByteLength(); got != int64(len(owned)) {
		t.Fatalf("source bytes = %d, want %d", got, len(owned))
	}

	var methods []string
	for _, operation := range snapshot.Operations().Operations() {
		typed, err := FromR3(operation)
		if err != nil {
			t.Fatal(err)
		}
		methods = append(methods, typed.Method())
		if _, present, err := snapshot.HintsFor(operation); err != nil || present {
			t.Fatalf("HintsFor(%q) present = %v, err = %v; gRPC has no annotation vocabulary", typed.Method(), present, err)
		}
	}
	want := []string{
		"example.admin.Admin/Ping",
		"example.calendar.Calendar/Read",
		"example.calendar.Calendar/Write",
	}
	if !slices.Equal(methods, want) {
		t.Fatalf("methods = %v, want %v", methods, want)
	}

	known := mustDefinitionOperationSet(t, "example.calendar.Calendar/Read")
	if err := snapshot.ValidateDefined(known); err != nil {
		t.Fatalf("ValidateDefined(known) = %v", err)
	}
	unknown := mustDefinitionOperationSet(t, "example.calendar.Calendar/Delete")
	assertDefinitionError(t, snapshot.ValidateDefined(unknown), r3.DefinitionOperationNotDefined)

	registry, err := r3.NewDefinitionRegistry(DefinitionRegistration())
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Validate(snapshot); err != nil {
		t.Fatalf("definition registry refused package snapshot: %v", err)
	}
}

func TestParseDefinitionRefusesMissingImports(t *testing.T) {
	source := NewDescriptorSetSource(mustMarshalDescriptorSet(t, &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{{
		Name:       proto.String("calendar.proto"),
		Package:    proto.String("example.calendar"),
		Syntax:     proto.String("proto3"),
		Dependency: []string{"missing.proto"},
	}}}))
	_, err := ParseDefinition(definitionEndpoint, source)
	assertDefinitionError(t, err, r3.DefinitionUnresolvedDependency)
}

func TestParseDefinitionRefusesIncompleteDescriptorSets(t *testing.T) {
	tests := []struct {
		name string
		set  *descriptorpb.FileDescriptorSet
	}{
		{name: "no files", set: &descriptorpb.FileDescriptorSet{}},
		{name: "nil file", set: &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{nil}}},
		{name: "missing file name", set: &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{{Package: proto.String("example.calendar")}}}},
		{name: "service without package", set: &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{{Name: proto.String("calendar.proto"), Service: []*descriptorpb.ServiceDescriptorProto{{Name: proto.String("Calendar")}}}}}},
		{name: "method without input", set: descriptorSetWithMethod(&descriptorpb.MethodDescriptorProto{Name: proto.String("Read"), OutputType: proto.String(".example.calendar.Response")})},
		{name: "method without output", set: descriptorSetWithMethod(&descriptorpb.MethodDescriptorProto{Name: proto.String("Read"), InputType: proto.String(".example.calendar.Request")})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseDefinition(definitionEndpoint, NewDescriptorSetSource(mustMarshalDescriptorSet(t, test.set)))
			assertDefinitionError(t, err, r3.DefinitionIncompleteSource)
		})
	}
}

func TestParseDefinitionRefusesDuplicateAndInvalidMethodIdentities(t *testing.T) {
	duplicate := &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{
		serviceFile("left.proto", "example.calendar", "Calendar", "Read"),
		serviceFile("right.proto", "example.calendar", "Calendar", "Read"),
	}}
	_, err := ParseDefinition(definitionEndpoint, NewDescriptorSetSource(mustMarshalDescriptorSet(t, duplicate)))
	assertDefinitionError(t, err, r3.DefinitionIdentityAmbiguous)

	invalid := descriptorSetWithMethod(&descriptorpb.MethodDescriptorProto{
		Name:       proto.String("not-valid"),
		InputType:  proto.String(".example.calendar.Request"),
		OutputType: proto.String(".example.calendar.Response"),
	})
	_, err = ParseDefinition(definitionEndpoint, NewDescriptorSetSource(mustMarshalDescriptorSet(t, invalid)))
	assertDefinitionError(t, err, r3.DefinitionIdentityUnavailable)
}

func TestParseDefinitionRefusesMalformedDescriptorBytes(t *testing.T) {
	_, err := ParseDefinition(definitionEndpoint, NewDescriptorSetSource([]byte{0xff, 0xff}))
	assertDefinitionError(t, err, r3.DefinitionInvalidSource)
}

func TestParseDefinitionRefusesSourcesThatRequireAcquisition(t *testing.T) {
	tests := []struct {
		name   string
		source DefinitionSource
		kind   SourceKind
	}{
		{name: "hosted proto text", source: NewHostedProtoTextSource([]byte("syntax = \"proto3\";")), kind: SourceKindHostedProtoText},
		{name: "live server reflection", source: NewServerReflectionSource(), kind: SourceKindServerReflection},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.source.Kind(); got != test.kind {
				t.Fatalf("source kind = %q, want %q", got, test.kind)
			}
			_, err := ParseDefinition(definitionEndpoint, test.source)
			assertDefinitionError(t, err, r3.DefinitionSourceKindUnsupported)
		})
	}
}

func TestParseDefinitionHandlesPointerSourceForms(t *testing.T) {
	descriptor := NewDescriptorSetSource(mustMarshalDescriptorSet(t, descriptorSetWithMethod(
		&descriptorpb.MethodDescriptorProto{
			Name:       proto.String("Read"),
			InputType:  proto.String(".example.calendar.Request"),
			OutputType: proto.String(".example.calendar.Response"),
		},
	)))
	if _, err := ParseDefinition(definitionEndpoint, &descriptor); err != nil {
		t.Fatalf("descriptor pointer was refused: %v", err)
	}
	hosted := NewHostedProtoTextSource([]byte(`syntax = "proto3";`))
	_, err := ParseDefinition(definitionEndpoint, &hosted)
	assertDefinitionError(t, err, r3.DefinitionSourceKindUnsupported)

	var absent *DescriptorSetSource
	_, err = ParseDefinition(definitionEndpoint, absent)
	assertDefinitionError(t, err, r3.DefinitionIncompleteSource)
}

func descriptorSetWithMethod(method *descriptorpb.MethodDescriptorProto) *descriptorpb.FileDescriptorSet {
	file := serviceFile("calendar.proto", "example.calendar", "Calendar", "placeholder")
	file.MessageType = []*descriptorpb.DescriptorProto{{Name: proto.String("Request")}, {Name: proto.String("Response")}}
	file.Service[0].Method = []*descriptorpb.MethodDescriptorProto{method}
	return &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{file}}
}

func serviceFile(name, pkg, service, method string) *descriptorpb.FileDescriptorProto {
	return &descriptorpb.FileDescriptorProto{
		Name:    proto.String(name),
		Package: proto.String(pkg),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: proto.String("Request")},
			{Name: proto.String("Response")},
		},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: proto.String(service),
			Method: []*descriptorpb.MethodDescriptorProto{{
				Name:       proto.String(method),
				InputType:  proto.String("." + pkg + ".Request"),
				OutputType: proto.String("." + pkg + ".Response"),
			}},
		}},
	}
}

func mustMarshalDescriptorSet(t *testing.T, set *descriptorpb.FileDescriptorSet) []byte {
	t.Helper()
	encoded, err := proto.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mustDefinitionOperationSet(t *testing.T, method string) r3.OperationSet {
	t.Helper()
	operation, err := NewOperation(method)
	if err != nil {
		t.Fatal(err)
	}
	set, err := NewOperationSet(operation)
	if err != nil {
		t.Fatal(err)
	}
	return set
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
