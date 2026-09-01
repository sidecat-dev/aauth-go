package main

import (
	"errors"
	"fmt"
	"os"
)

func main() {
	os.Exit(runHostedCLI(os.Args[1:]))
}

func runHostedCLI(arguments []string) int {
	if len(arguments) == 0 {
		fmt.Fprintln(os.Stderr, "usage: aauth-hosted host-init|agent-init|serve|health|connect|host-status|login|link|account-status|approve|act")
		return 2
	}
	var err error
	switch arguments[0] {
	case "host-init":
		err = hostInitCommand(arguments[1:])
	case "agent-init":
		err = agentInitCommand(arguments[1:])
	case "serve":
		err = serveCommand(arguments[1:])
	case "health", "connect", "host-status":
		err = agentCommand(arguments[0], arguments[1:])
	case "login", "link", "account-status", "approve", "revoke":
		err = accountCommand(arguments[0], arguments[1:])
	case "act":
		err = actCommand(arguments[1:])
	default:
		err = fmt.Errorf("unknown command %q", arguments[0])
	}
	if err == nil {
		return 0
	}
	var remote *hostedRemoteError
	if errors.As(err, &remote) {
		fmt.Fprint(os.Stderr, remote.body)
	} else {
		fmt.Fprintln(os.Stderr, "aauth-hosted:", err)
	}
	return 1
}
