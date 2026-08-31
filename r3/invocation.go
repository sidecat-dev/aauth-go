package r3

import (
	"errors"
	"fmt"
)

// Invocation is one transport-independent operation and the concrete
// parameter values presented for that call. It owns no request, token,
// execution, result, or retention state.
type Invocation struct {
	operation  Operation
	parameters map[string]PresentedParameter
}

// NewInvocation constructs an owned call-time view for R3 enforcement and
// proposal matching. An empty parameter set is valid.
func NewInvocation(operation Operation, parameters map[string]PresentedParameter) (Invocation, error) {
	if operation.JSON() == nil {
		return Invocation{}, fmt.Errorf("r3: invocation operation is invalid")
	}
	owned := make(map[string]PresentedParameter, len(parameters))
	for name, parameter := range parameters {
		if err := validateParameterName(name); err != nil {
			return Invocation{}, err
		}
		if err := parameter.validate(); err != nil {
			return Invocation{}, fmt.Errorf("r3: invocation parameter %q: %w", name, err)
		}
		owned[name] = parameter.clone()
	}
	return Invocation{operation: operation, parameters: owned}, nil
}

// Operation returns the registered operation being invoked.
func (invocation Invocation) Operation() Operation {
	return invocation.operation
}

// PresentedParameters returns an independently owned parameter map.
func (invocation Invocation) PresentedParameters() map[string]PresentedParameter {
	parameters := make(map[string]PresentedParameter, len(invocation.parameters))
	for name, parameter := range invocation.parameters {
		parameters[name] = parameter.clone()
	}
	return parameters
}

// MarshalJSON refuses to encode this runtime-only call view as a protocol
// value.
func (Invocation) MarshalJSON() ([]byte, error) {
	return nil, errors.New("r3: Invocation is not a wire value")
}

// UnmarshalJSON refuses to construct a runtime call view from untrusted JSON.
func (*Invocation) UnmarshalJSON([]byte) error {
	return errors.New("r3: Invocation is not a wire value; use NewInvocation")
}
