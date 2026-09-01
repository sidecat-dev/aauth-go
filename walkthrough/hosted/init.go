package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
)

func hostInitCommand(arguments []string) error {
	flags := flag.NewFlagSet("host-init", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	stateDir := flags.String("state", "", "host state directory")
	listen := flags.String("listen", "", "TLS listen address")
	origin := flags.String("origin", "", "public HTTPS origin")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *stateDir == "" || *listen == "" || *origin == "" || flags.NArg() != 0 {
		return errors.New("host-init requires --state DIR --listen ADDRESS --origin HTTPS_ORIGIN")
	}
	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(hostConfigPath(*stateDir)); err == nil {
		return errors.New("host state is already initialized")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := initializeHostPKI(*stateDir, *origin); err != nil {
		return err
	}
	if err := createHostedSigningKey(*stateDir, "person"); err != nil {
		return err
	}
	if err := createHostedSigningKey(*stateDir, "resource"); err != nil {
		return err
	}
	enrollmentCode, err := randomSecret()
	if err != nil {
		return err
	}
	controlToken, err := randomSecret()
	if err != nil {
		return err
	}
	config := hostConfig{Listen: *listen, Origin: *origin, EnrollmentCode: enrollmentCode, ControlToken: controlToken}
	if err := writeJSONFile(hostConfigPath(*stateDir), 0o600, config); err != nil {
		return err
	}
	ca, err := os.ReadFile(filepath.Join(*stateDir, "ca.pem"))
	if err != nil {
		return err
	}
	bootstrap := bootstrapDocument{Origin: *origin, CAPEM: string(ca), EnrollmentCode: enrollmentCode, ControlToken: controlToken}
	if err := writeJSONFile(filepath.Join(*stateDir, "bootstrap.json"), 0o600, bootstrap); err != nil {
		return err
	}
	password, err := randomSecret()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*stateDir, "user-password"), []byte(password+"\n"), 0o600); err != nil {
		return err
	}
	if err := initializeAccountStore(filepath.Join(*stateDir, "account-store.json"), "person@example.test", password); err != nil {
		return err
	}
	if err := initializeHostedProtocolStore(filepath.Join(*stateDir, "protocol-store.json")); err != nil {
		return err
	}
	return writeJSONFile(filepath.Join(*stateDir, "enrollment-store.json"), 0o600, enrollmentStoreState{
		Enrollments: map[string]agentprovider.EnrollmentRecord{},
		Refreshes:   map[string]agentprovider.RefreshRecord{},
	})
}

func agentInitCommand(arguments []string) error {
	flags := flag.NewFlagSet("agent-init", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	stateDir := flags.String("state", "", "Agent state directory")
	bootstrapPath := flags.String("bootstrap", "", "host bootstrap document")
	serviceAddress := flags.String("service-address", "", "optional network address override")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *stateDir == "" || *bootstrapPath == "" || flags.NArg() != 0 {
		return errors.New("agent-init requires --state DIR --bootstrap FILE")
	}
	var bootstrap bootstrapDocument
	if err := readJSON(*bootstrapPath, &bootstrap); err != nil {
		return fmt.Errorf("read bootstrap document: %w", err)
	}
	if bootstrap.Origin == "" || bootstrap.CAPEM == "" || bootstrap.EnrollmentCode == "" || bootstrap.ControlToken == "" {
		return errors.New("bootstrap document is incomplete")
	}
	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(agentConfigPath(*stateDir)); err == nil {
		return errors.New("Agent state is already initialized")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.WriteFile(filepath.Join(*stateDir, "ca.pem"), []byte(bootstrap.CAPEM), 0o644); err != nil {
		return err
	}
	if err := createHostedSigningKey(*stateDir, "durable"); err != nil {
		return err
	}
	if err := createHostedSigningKey(*stateDir, "agent"); err != nil {
		return err
	}
	config := agentConfig{ServiceOrigin: bootstrap.Origin, ServiceAddress: *serviceAddress, EnrollmentCode: bootstrap.EnrollmentCode, ControlToken: bootstrap.ControlToken}
	return writeJSONFile(agentConfigPath(*stateDir), 0o600, config)
}
