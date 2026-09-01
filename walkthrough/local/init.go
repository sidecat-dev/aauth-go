package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

func initCommand(arguments []string) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	stateDir := flags.String("state", "", "walkthrough state directory")
	agentAddress := flags.String("agent-address", "", "agent listen address")
	serviceAddress := flags.String("service-address", "", "service listen address")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *stateDir == "" || *agentAddress == "" || *serviceAddress == "" || flags.NArg() != 0 {
		return fmt.Errorf("init requires --state DIR --agent-address HOST:PORT --service-address HOST:PORT")
	}
	for _, address := range []string{*agentAddress, *serviceAddress} {
		host, _, err := net.SplitHostPort(address)
		if err != nil || host != "127.0.0.1" {
			return fmt.Errorf("walkthrough process address %q must use 127.0.0.1 and an explicit port", address)
		}
	}
	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(configPath(*stateDir)); err == nil {
		return fmt.Errorf("state directory is already initialized")
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := initializePKI(*stateDir); err != nil {
		return fmt.Errorf("initialize keys and certificates: %w", err)
	}
	controlSecret := make([]byte, 32)
	if _, err := rand.Read(controlSecret); err != nil {
		return fmt.Errorf("generate control credential: %w", err)
	}
	if err := os.WriteFile(
		filepath.Join(*stateDir, "control.token"),
		[]byte(base64.RawURLEncoding.EncodeToString(controlSecret)+"\n"),
		0o600,
	); err != nil {
		return err
	}
	config := walkthroughConfig{AgentAddress: *agentAddress, ServiceAddress: *serviceAddress}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(configPath(*stateDir), encoded, 0o600); err != nil {
		return err
	}
	return nil
}
