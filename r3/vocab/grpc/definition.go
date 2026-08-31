package grpc

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"gitlab.com/sidecat-dev/aauth-go/r3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

// SourceKind distinguishes the native representations from which a gRPC
// operation definition might be acquired. This package parses complete binary
// descriptor sets only; it performs no network, reflection, or .proto loading.
type SourceKind string

const (
	// SourceKindDescriptorSet identifies complete binary descriptor input.
	SourceKindDescriptorSet SourceKind = "file-descriptor-set"
	// SourceKindHostedProtoText identifies .proto text requiring compilation.
	SourceKindHostedProtoText SourceKind = "hosted-proto-text"
	// SourceKindServerReflection identifies live reflection requiring acquisition.
	SourceKindServerReflection SourceKind = "server-reflection"
)

// DefinitionSource is one already-acquired gRPC definition input. Its sealed
// implementations keep unsupported acquisition forms distinct from descriptor
// bytes instead of silently guessing how an HTTPS endpoint should be used.
type DefinitionSource interface {
	Kind() SourceKind
	grpcDefinitionSource()
}

// DescriptorSetSource owns the exact binary google.protobuf.FileDescriptorSet
// passed by the caller.
type DescriptorSetSource struct{ exact []byte }

// NewDescriptorSetSource copies an exact binary FileDescriptorSet.
func NewDescriptorSetSource(exact []byte) DescriptorSetSource {
	return DescriptorSetSource{exact: append([]byte(nil), exact...)}
}

func (DescriptorSetSource) Kind() SourceKind      { return SourceKindDescriptorSet }
func (DescriptorSetSource) grpcDefinitionSource() {}

// HostedProtoTextSource identifies already-acquired .proto source text. The
// parser refuses it because import resolution and compilation belong outside
// the authoritative-definition boundary.
type HostedProtoTextSource struct{ exact []byte }

// NewHostedProtoTextSource copies hosted .proto source for an explicit typed
// refusal; it does not compile or resolve imports.
func NewHostedProtoTextSource(exact []byte) HostedProtoTextSource {
	return HostedProtoTextSource{exact: append([]byte(nil), exact...)}
}

func (HostedProtoTextSource) Kind() SourceKind      { return SourceKindHostedProtoText }
func (HostedProtoTextSource) grpcDefinitionSource() {}

// ServerReflectionSource identifies a live server-reflection acquisition.
// ParseDefinition never contacts that server.
type ServerReflectionSource struct{}

// NewServerReflectionSource constructs an explicit live-reflection source.
func NewServerReflectionSource() ServerReflectionSource { return ServerReflectionSource{} }

func (ServerReflectionSource) Kind() SourceKind      { return SourceKindServerReflection }
func (ServerReflectionSource) grpcDefinitionSource() {}

const descriptorSetEncoding r3.SourceEncoding = "application/x-protobuf;message=google.protobuf.FileDescriptorSet"

type definitionCodec struct{}

func (definitionCodec) Vocabulary() r3.Vocabulary { return Vocabulary() }

func (definitionCodec) ParseDefinition(source DefinitionSource) (r3.DefinitionMaterial, error) {
	var descriptorSource DescriptorSetSource
	switch source := source.(type) {
	case HostedProtoTextSource:
		return r3.DefinitionMaterial{}, definitionError(
			r3.DefinitionSourceKindUnsupported,
			"hosted .proto text must be compiled and dependency-resolved into a complete FileDescriptorSet before parsing",
			nil,
		)
	case *HostedProtoTextSource:
		if source == nil {
			return r3.DefinitionMaterial{}, definitionError(r3.DefinitionIncompleteSource, "gRPC definition source is absent", nil)
		}
		return r3.DefinitionMaterial{}, definitionError(
			r3.DefinitionSourceKindUnsupported,
			"hosted .proto text must be compiled and dependency-resolved into a complete FileDescriptorSet before parsing",
			nil,
		)
	case ServerReflectionSource:
		return r3.DefinitionMaterial{}, definitionError(
			r3.DefinitionSourceKindUnsupported,
			"live server reflection must be acquired into a complete FileDescriptorSet before parsing",
			nil,
		)
	case *ServerReflectionSource:
		if source == nil {
			return r3.DefinitionMaterial{}, definitionError(r3.DefinitionIncompleteSource, "gRPC definition source is absent", nil)
		}
		return r3.DefinitionMaterial{}, definitionError(
			r3.DefinitionSourceKindUnsupported,
			"live server reflection must be acquired into a complete FileDescriptorSet before parsing",
			nil,
		)
	case DescriptorSetSource:
		descriptorSource = source
	case *DescriptorSetSource:
		if source == nil {
			return r3.DefinitionMaterial{}, definitionError(r3.DefinitionIncompleteSource, "gRPC definition source is absent", nil)
		}
		descriptorSource = *source
	default:
		return r3.DefinitionMaterial{}, definitionError(r3.DefinitionIncompleteSource, "gRPC definition source is absent", nil)
	}
	var descriptorSet descriptorpb.FileDescriptorSet
	if err := proto.Unmarshal(descriptorSource.exact, &descriptorSet); err != nil {
		return r3.DefinitionMaterial{}, definitionError(r3.DefinitionInvalidSource, "invalid binary FileDescriptorSet", err)
	}
	if err := validateDescriptorSetStructure(&descriptorSet); err != nil {
		return r3.DefinitionMaterial{}, err
	}
	files, err := protodesc.NewFiles(&descriptorSet)
	if err != nil {
		return r3.DefinitionMaterial{}, definitionError(r3.DefinitionInvalidSource, "invalid linked protobuf descriptors", err)
	}

	var methods []string
	files.RangeFiles(func(file protoreflect.FileDescriptor) bool {
		services := file.Services()
		for serviceIndex := 0; serviceIndex < services.Len(); serviceIndex++ {
			service := services.Get(serviceIndex)
			serviceMethods := service.Methods()
			for methodIndex := 0; methodIndex < serviceMethods.Len(); methodIndex++ {
				method := serviceMethods.Get(methodIndex)
				methods = append(methods, string(service.FullName())+"/"+string(method.Name()))
			}
		}
		return true
	})
	if len(methods) == 0 {
		return r3.DefinitionMaterial{}, definitionError(r3.DefinitionIncompleteSource, "FileDescriptorSet defines no service methods", nil)
	}
	sort.Strings(methods)
	operations := make([]r3.DefinedOperation, len(methods))
	for index, method := range methods {
		operation, err := NewOperation(method)
		if err != nil {
			return r3.DefinitionMaterial{}, definitionError(r3.DefinitionIdentityUnavailable, "invalid gRPC method identity", err)
		}
		if index > 0 && methods[index-1] == method {
			return r3.DefinitionMaterial{}, definitionError(r3.DefinitionIdentityAmbiguous, fmt.Sprintf("gRPC method %q occurs more than once", method), nil)
		}
		encoded, err := json.Marshal(operation)
		if err != nil {
			return r3.DefinitionMaterial{}, err
		}
		operations[index], err = r3.NewDefinedOperation(encoded, nil)
		if err != nil {
			return r3.DefinitionMaterial{}, err
		}
	}
	return r3.NewDefinitionMaterial(descriptorSetEncoding, descriptorSource.exact, operations...)
}

func validateDescriptorSetStructure(set *descriptorpb.FileDescriptorSet) error {
	if set == nil || len(set.File) == 0 {
		return definitionError(r3.DefinitionIncompleteSource, "FileDescriptorSet contains no files", nil)
	}
	files := make(map[string]struct{}, len(set.File))
	methods := make(map[string]struct{})
	for index, file := range set.File {
		if file == nil {
			return definitionError(r3.DefinitionIncompleteSource, fmt.Sprintf("FileDescriptorSet file %d is absent", index), nil)
		}
		if file.GetName() == "" {
			return definitionError(r3.DefinitionIncompleteSource, fmt.Sprintf("FileDescriptorSet file %d has no name", index), nil)
		}
		if _, duplicate := files[file.GetName()]; duplicate {
			return definitionError(r3.DefinitionInvalidSource, fmt.Sprintf("FileDescriptorSet repeats file %q", file.GetName()), nil)
		}
		files[file.GetName()] = struct{}{}
	}
	for fileIndex, file := range set.File {
		for _, dependency := range file.Dependency {
			if _, present := files[dependency]; !present {
				return definitionError(r3.DefinitionUnresolvedDependency, fmt.Sprintf("file %q imports missing descriptor %q", file.GetName(), dependency), nil)
			}
		}
		if len(file.Service) > 0 && file.GetPackage() == "" {
			return definitionError(r3.DefinitionIncompleteSource, fmt.Sprintf("file %q defines services without a package", file.GetName()), nil)
		}
		for serviceIndex, service := range file.Service {
			if service == nil || service.GetName() == "" {
				return definitionError(r3.DefinitionIncompleteSource, fmt.Sprintf("file %d service %d has no identity", fileIndex, serviceIndex), nil)
			}
			for methodIndex, method := range service.Method {
				if method == nil || method.GetName() == "" || method.GetInputType() == "" || method.GetOutputType() == "" {
					return definitionError(r3.DefinitionIncompleteSource, fmt.Sprintf("file %q service %q method %d is incomplete", file.GetName(), service.GetName(), methodIndex), nil)
				}
				identity := file.GetPackage() + "." + service.GetName() + "/" + method.GetName()
				if _, err := NewOperation(identity); err != nil {
					return definitionError(r3.DefinitionIdentityUnavailable, fmt.Sprintf("invalid gRPC method identity %q", identity), err)
				}
				if _, duplicate := methods[identity]; duplicate {
					return definitionError(r3.DefinitionIdentityAmbiguous, fmt.Sprintf("gRPC method %q occurs more than once", identity), nil)
				}
				methods[identity] = struct{}{}
			}
		}
	}
	return nil
}

var (
	definitionParserOnce   sync.Once
	sharedDefinitionParser r3.DefinitionParser[DefinitionSource]
)

func parser() r3.DefinitionParser[DefinitionSource] {
	definitionParserOnce.Do(func() {
		var err error
		sharedDefinitionParser, err = r3.NewDefinitionParser[DefinitionSource](definitionCodec{})
		if err != nil {
			panic(err)
		}
	})
	return sharedDefinitionParser
}

// ParseDefinition validates a complete binary FileDescriptorSet and derives
// every fully qualified gRPC service method. It performs no I/O.
func ParseDefinition(endpoint string, source DefinitionSource) (r3.AuthoritativeSnapshot, error) {
	return parser().Parse(endpoint, source)
}

// DefinitionRegistration returns the stable gRPC parser registration.
func DefinitionRegistration() r3.DefinitionRegistration {
	return parser().Registration()
}

func definitionError(kind r3.DefinitionErrorKind, reason string, cause error) error {
	return r3.NewDefinitionError(kind, reason, cause)
}

var _ r3.DefinitionCodec[DefinitionSource] = definitionCodec{}
