package agent_test

import (
	"errors"
	"fmt"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// A Client method returns an *agent.Error that wraps the server's refusal.
func ExampleError() {
	// err stands for what a Client method returned.
	var err error = &agent.Error{
		Operation: "do",
		Cause:     &signaturekey.Error{Code: signaturekey.ErrorExpiredJWT},
	}

	var signature *signaturekey.Error
	var problem *aauth.ProblemError
	switch {
	case errors.As(err, &signature):
		// signature.Code is the Signature-Error code.
		fmt.Println("Signature-Error:", signature.Code)
	case errors.As(err, &problem):
		// problem.Code is the error member of the body; problem.Status the HTTP status.
		fmt.Println("refused:", problem.Status, problem.Code)
	}
	// Output: Signature-Error: expired_jwt
}
