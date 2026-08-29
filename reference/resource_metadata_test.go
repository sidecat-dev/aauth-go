package reference

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestHTTPResourceMetadataResolverReturnsVerifiedPresentation(t *testing.T) {
	t.Parallel()
	client := &http.Client{Transport: resourceMetadataRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.String() != "https://resource.example/.well-known/aauth-resource.json" ||
			request.Header.Get("Accept") != "application/json" {
			t.Fatalf("resource metadata request = %s %s, accept %q", request.Method, request.URL, request.Header.Get("Accept"))
		}
		return resourceMetadataResponse(http.StatusOK, `{
			"issuer":"https://resource.example",
			"name":"Example Documents",
			"description":"**Example Documents** stores files.",
			"access_mode":"auth-token",
			"extension":{"preserved":"by its owner"}
		}`), nil
	})}
	resolver, err := NewHTTPResourceMetadataResolver(client)
	if err != nil {
		t.Fatal(err)
	}
	presentation, err := resolver.ResolveResourceMetadata(context.Background(), "https://resource.example")
	if err != nil {
		t.Fatal(err)
	}
	want := aauth.ResourcePresentation{
		Issuer:      "https://resource.example",
		Name:        "Example Documents",
		Description: "**Example Documents** stores files.",
		AccessMode:  aauth.AccessModeAuthToken,
	}
	if presentation != want {
		t.Fatalf("resource presentation = %#v, want %#v", presentation, want)
	}
}

func TestHTTPResourceMetadataResolverClassifiesRefusals(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		do   func(*http.Request) (*http.Response, error)
		code ResourceMetadataErrorCode
	}{
		{
			name: "unavailable transport",
			do: func(*http.Request) (*http.Response, error) {
				return nil, errors.New("network unavailable")
			},
			code: ResourceMetadataUnavailable,
		},
		{
			name: "unavailable response",
			do: func(*http.Request) (*http.Response, error) {
				return resourceMetadataResponse(http.StatusServiceUnavailable, `{"error":"busy"}`), nil
			},
			code: ResourceMetadataUnavailable,
		},
		{
			name: "malformed document",
			do: func(*http.Request) (*http.Response, error) {
				return resourceMetadataResponse(http.StatusOK, `{"issuer":`), nil
			},
			code: ResourceMetadataInvalid,
		},
		{
			name: "ambiguous document",
			do: func(*http.Request) (*http.Response, error) {
				return resourceMetadataResponse(http.StatusOK, `{"issuer":"https://resource.example","ISSUER":"https://other.example"}`), nil
			},
			code: ResourceMetadataInvalid,
		},
		{
			name: "issuer mismatch",
			do: func(*http.Request) (*http.Response, error) {
				return resourceMetadataResponse(http.StatusOK, `{"issuer":"https://other.example"}`), nil
			},
			code: ResourceMetadataInvalid,
		},
		{
			name: "null optional field",
			do: func(*http.Request) (*http.Response, error) {
				return resourceMetadataResponse(http.StatusOK, `{"issuer":"https://resource.example","description":null}`), nil
			},
			code: ResourceMetadataInvalid,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			resolver, err := NewHTTPResourceMetadataResolver(&http.Client{Transport: resourceMetadataRoundTripFunc(test.do)})
			if err != nil {
				t.Fatal(err)
			}
			_, err = resolver.ResolveResourceMetadata(context.Background(), "https://resource.example")
			var metadataError *ResourceMetadataError
			if !errors.As(err, &metadataError) || metadataError.Code != test.code {
				t.Fatalf("resource metadata error = %v, want code %q", err, test.code)
			}
		})
	}
}

func TestResourceMetadataFailuresUseTokenEndpointProblemCodes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{
			name: "invalid metadata",
			err: &ResourceMetadataError{
				Code: ResourceMetadataInvalid, Cause: errors.New("hostile issuer details must stay local"),
			},
			status: http.StatusBadRequest,
			code:   "invalid_request",
		},
		{
			name: "unavailable metadata",
			err: &ResourceMetadataError{
				Code: ResourceMetadataUnavailable, Cause: errors.New("internal network details must stay local"),
			},
			status: http.StatusServiceUnavailable,
			code:   "server_error",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			response := httptest.NewRecorder()
			writeResourceMetadataFailure(response, test.err)
			if response.Code != test.status {
				t.Fatalf("problem status = %d, want %d", response.Code, test.status)
			}
			body := response.Body.String()
			if !strings.Contains(body, `"error":"`+test.code+`"`) ||
				strings.Contains(body, "hostile issuer") || strings.Contains(body, "internal network") {
				t.Fatalf("problem body = %s", body)
			}
		})
	}
}

type resourceMetadataRoundTripFunc func(*http.Request) (*http.Response, error)

func (function resourceMetadataRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func resourceMetadataResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
