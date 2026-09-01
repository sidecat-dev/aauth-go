package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

func main() {
	os.Exit(runCLI(os.Args[1:]))
}

func runCLI(arguments []string) int {
	if len(arguments) == 0 {
		fmt.Fprintln(os.Stderr, "usage: aauth-local init|agent|service|act|revoke|status")
		return 2
	}
	var err error
	switch arguments[0] {
	case "init":
		err = initCommand(arguments[1:])
	case "agent":
		err = processCommand("agent", arguments[1:])
	case "service":
		err = processCommand("service", arguments[1:])
	case "act":
		err = actCommand(arguments[1:])
	case "revoke":
		err = simpleClientCommand("revoke", arguments[1:])
	case "status":
		err = simpleClientCommand("status", arguments[1:])
	default:
		err = fmt.Errorf("unknown command %q", arguments[0])
	}
	if err == nil {
		return 0
	}
	var remote *remoteError
	if errors.As(err, &remote) {
		fmt.Fprint(os.Stderr, remote.body)
	} else {
		fmt.Fprintln(os.Stderr, "aauth-local:", err)
	}
	return 1
}

func stateFlag(name string, arguments []string) (string, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	state := flags.String("state", "", "walkthrough state directory")
	if err := flags.Parse(arguments); err != nil {
		return "", err
	}
	if *state == "" || flags.NArg() != 0 {
		return "", fmt.Errorf("%s requires --state DIR", name)
	}
	return *state, nil
}
