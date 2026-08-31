package resource

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
)

func TestR3HTTPAdapterProducesANeutralInvocation(t *testing.T) {
	config := newResourceMCPConfig(t, &r3TestDocumentStore{}, []string{"records.read"}, nil)
	config.HTTP = R3HTTPAdapter{
		OperationForRequest: func(request *http.Request) (r3.Operation, bool, error) {
			if request.URL.Path != "/records" {
				return r3.Operation{}, false, nil
			}
			typed, err := mcp.NewOperation("records.read")
			if err != nil {
				return r3.Operation{}, false, err
			}
			operation, err := typed.ToR3()
			return operation, err == nil, err
		},
		PresentParameters: func(*http.Request, r3.Operation) (map[string]r3.PresentedParameter, error) {
			return map[string]r3.PresentedParameter{}, nil
		},
	}

	serverConfig := validConfig(t, http.NotFoundHandler())
	serverConfig.R3 = config
	server, err := NewFederatedAuthorization(serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://resource.example/records", nil)
	operation, mapped, err := server.r3OperationForRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if !mapped {
		t.Fatal("HTTP adapter did not map the request")
	}
	invocation, err := server.r3InvocationForRequest(request, operation)
	if err != nil {
		t.Fatal(err)
	}
	typed, err := mcp.FromR3(invocation.Operation())
	if err != nil {
		t.Fatal(err)
	}
	if typed.Tool() != "records.read" {
		t.Fatalf("operation = %q", typed.Tool())
	}
}

func TestR3HTTPAdapterRejectsMappedOperationAbsentFromDefinition(t *testing.T) {
	config := newResourceMCPConfig(
		t,
		&r3TestDocumentStore{},
		[]string{"records.read"},
		func(*http.Request) (string, bool, error) {
			return "records.delete", true, nil
		},
	)
	serverConfig := validConfig(t, http.NotFoundHandler())
	serverConfig.R3 = config
	server, err := NewFederatedAuthorization(serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodDelete, "https://resource.example/records/1", nil)
	operation, mapped, err := server.r3OperationForRequest(request)
	if operation.JSON() != nil || mapped {
		t.Fatalf("rejected mapping returned operation=%s mapped=%t", operation.JSON(), mapped)
	}
	var refusal *r3.DefinitionError
	if !errors.As(err, &refusal) || refusal.Kind != r3.DefinitionOperationNotDefined {
		t.Fatalf("mapped-operation refusal = %T %v", err, err)
	}
}
