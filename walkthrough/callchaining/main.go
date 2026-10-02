// Command aauth-callchain demonstrates one immediate call chain over local TLS.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("usage: aauth-callchain init|serve|call|probe|status --state DIR")
	}
	command := arguments[0]
	if command == "-h" || command == "--help" || command == "help" {
		_, err := fmt.Fprint(os.Stdout, `Usage: aauth-callchain COMMAND [options]

Demonstrate one two-resource call chain over four local TLS processes.

Commands:
  init    Generate private setup material and temporary TLS certificates.
  serve   Run one role: agent, person, orders, or inventory.
  call    Authorize orders.fulfill and perform one inventory.reserve action.
  probe   Check refusal of an unsigned or expired credential.
  status  Inspect all four roles and Inventory's action count.

Run aauth-callchain COMMAND --help for command options.
See README.md for setup and shell commands to start and stop the four processes
using their process IDs. There are no separate start or stop commands.
`)
		return err
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	state := flags.String("state", "", "temporary private walkthrough state directory")
	var role, kind string
	addresses := map[string]*string{}
	switch command {
	case "init":
		for i, name := range roles {
			addresses[name] = flags.String(name+"-address", fmt.Sprintf("127.0.0.1:%d", 18443+i*1000), "loopback TCP listener for "+name)
		}
	case "serve":
		flags.StringVar(&role, "role", "", "agent, person, orders, or inventory")
	case "probe":
		flags.StringVar(&kind, "kind", "", "unsigned or expired")
	case "call", "status":
	default:
		return fmt.Errorf("unknown command %q", command)
	}
	for _, argument := range arguments[1:] {
		if argument == "-h" || argument == "--help" {
			flags.SetOutput(os.Stdout)
			break
		}
	}
	if err := flags.Parse(arguments[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *state == "" || flags.NArg() != 0 {
		return errors.New("--state DIR is required; positional arguments are not accepted")
	}
	if command == "init" {
		listeners := make(map[string]string)
		for name, address := range addresses {
			listeners[name] = *address
		}
		return initialize(*state, listeners)
	}
	config, err := loadConfig(*state)
	if err != nil {
		return err
	}
	switch command {
	case "serve":
		return serve(*state, config, role)
	case "call":
		return call(context.Background(), *state, config)
	case "probe":
		return probe(context.Background(), *state, config, kind)
	case "status":
		result, err := status(context.Background(), *state, config)
		if err != nil {
			return err
		}
		return outputJSON(result)
	}
	return errors.New("unreachable command")
}

func outputJSON(value any) error { return json.NewEncoder(os.Stdout).Encode(value) }
