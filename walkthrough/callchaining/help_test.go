package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Help must be successful and useful before any setup or state access.
func TestCLIHelp(t *testing.T) {
	binary := helpTestBinary(t)
	for _, alias := range []string{"-h", "--help", "help"} {
		t.Run(alias, func(t *testing.T) {
			directory := t.TempDir()
			cmd := exec.Command(binary, alias)
			cmd.Dir = directory
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("help %s failed: %v\n%s", alias, err, output)
			}
			for _, needed := range []string{"init", "serve", "call", "probe", "status", "COMMAND --help", "README.md", "four", "start", "stop"} {
				if !strings.Contains(string(output), needed) {
					t.Errorf("overview lacks %q: %s", needed, output)
				}
			}
			assertHelpLeftDirectoryEmpty(t, directory)
		})
	}
	for _, command := range []string{"init", "serve", "call", "probe", "status"} {
		for _, alias := range []string{"-h", "--help"} {
			t.Run(command+alias, func(t *testing.T) {
				directory := t.TempDir()
				cmd := exec.Command(binary, command, alias)
				cmd.Dir = directory
				output, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("%s %s failed: %v\n%s", command, alias, err, output)
				}
				if !strings.Contains(string(output), command) || !strings.Contains(string(output), "-state") {
					t.Fatalf("command options unavailable: %s", output)
				}
				assertHelpLeftDirectoryEmpty(t, directory)
			})
		}
	}
}

func TestCLIErrorsRemainErrors(t *testing.T) {
	binary := helpTestBinary(t)
	for _, arguments := range [][]string{nil, {"unknown"}, {"serve"}, {"init", "--unknown"}} {
		directory := t.TempDir()
		cmd := exec.Command(binary, arguments...)
		cmd.Dir = directory
		output, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("invalid invocation %v succeeded: %s", arguments, output)
		}
		assertHelpLeftDirectoryEmpty(t, directory)
	}
}

func helpTestBinary(t *testing.T) string {
	t.Helper()
	if binary := os.Getenv("AAUTH_CALLCHAIN_BINARY"); binary != "" {
		return binary
	}
	binary := filepath.Join(t.TempDir(), "aauth-callchain")
	cmd := exec.Command("go", "build", "-p=1", "-o", binary, ".")
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build help consumer: %v\n%s", err, output)
	}
	return binary
}

func assertHelpLeftDirectoryEmpty(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("help or invalid invocation created state: %v", entries)
	}
}
