package main

import (
	"bytes"
	"testing"
)

func TestRunSupervisesOnePersonsAgentsUnderTwoSupervisors(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	if err := run(&output); err != nil {
		t.Fatal(err)
	}
	const want = "Personal supervisor connected after the person confirmed https://person.example\n" +
		"Work agent: builds.start granted by the organization's supervisor\n" +
		"Mission approved as refined: \"Ask before any payment.\"\n" +
		"Asked the person: The agent wants to pay an invoice. (supervisor recommends allow)\n" +
		"Person allowed it for the mission; the next payment was granted without asking\n" +
		"Personal supervisor offline: the person allowed the person-token request\n" +
		"Supervisor back online, told: decision.resolved (supervisor unavailable), person_token.issued\n" +
		"Signed decisions in the log verified: 3, each by https://supervisor.example\n"
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
	}
}
