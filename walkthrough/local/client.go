package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
)

func actCommand(arguments []string) error {
	flags := flag.NewFlagSet("act", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	stateDir := flags.String("state", "", "walkthrough state directory")
	requestKey := flags.String("request-key", "", "stable application request key")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *stateDir == "" || *requestKey == "" || flags.NArg() != 0 {
		return fmt.Errorf("act requires --state DIR --request-key KEY")
	}
	config, err := loadConfig(*stateDir)
	if err != nil {
		return err
	}
	client, err := newHTTPClient(*stateDir, config)
	if err != nil {
		return err
	}
	controlToken, err := loadControlToken(*stateDir)
	if err != nil {
		return err
	}
	encoded, err := requestJSON(
		client, http.MethodPost, agentOrigin+"/control/act",
		map[string]string{"request_key": *requestKey}, controlToken,
	)
	if err != nil {
		return err
	}
	fmt.Print(string(encoded))
	return nil
}

func simpleClientCommand(name string, arguments []string) error {
	stateDir, err := stateFlag(name, arguments)
	if err != nil {
		return err
	}
	config, err := loadConfig(stateDir)
	if err != nil {
		return err
	}
	client, err := newHTTPClient(stateDir, config)
	if err != nil {
		return err
	}
	method := http.MethodGet
	endpoint := resourceOrigin + "/status"
	bearer := ""
	if name == "revoke" {
		method = http.MethodPost
		endpoint = agentOrigin + "/control/revoke"
		bearer, err = loadControlToken(stateDir)
		if err != nil {
			return err
		}
	}
	encoded, err := requestJSON(client, method, endpoint, nil, bearer)
	if err != nil {
		return err
	}
	if name == "revoke" {
		var result map[string]string
		if err := json.Unmarshal(encoded, &result); err != nil || result["status"] != "revoked" {
			return fmt.Errorf("unexpected revocation response %q", encoded)
		}
		return nil
	}
	fmt.Print(string(encoded))
	return nil
}
