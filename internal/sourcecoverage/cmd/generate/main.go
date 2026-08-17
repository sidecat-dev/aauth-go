package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"gitlab.com/sidecat-dev/aauth-go/internal/sourcecoverage"
)

func main() {
	var (
		sourceDir = flag.String(
			"source-dir",
			"",
			"directory containing pinned sources (default: the retained repository copies)",
		)
		repoDir   = flag.String("repo", ".", "aauth-go repository root")
		manifest  = flag.String(
			"manifest",
			"internal/sourcecoverage/source-coverage.json",
			"coverage manifest",
		)
		inventory = flag.String(
			"inventory",
			"internal/sourcecoverage/source-section-inventory.json",
			"generated section inventory",
		)
		report = flag.String(
			"report",
			"SOURCE-COVERAGE.md",
			"generated human-readable report",
		)
	)
	flag.Parse()
	if flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	if *sourceDir == "" {
		*sourceDir = filepath.Join(*repoDir, "internal", "sourcecoverage", "sources")
	}
	if err := generate(
		*sourceDir,
		*repoDir,
		*manifest,
		*inventory,
		*report,
	); err != nil {
		fmt.Fprintln(os.Stderr, "generate source coverage:", err)
		os.Exit(1)
	}
}

func generate(
	sourceDir string,
	repoDir string,
	manifestPath string,
	inventoryPath string,
	reportPath string,
) error {
	manifestBody, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	manifest, err := sourcecoverage.DecodeManifest(manifestBody)
	if err != nil {
		return err
	}
	inventory, err := sourcecoverage.BuildInventory(manifest, sourceDir)
	if err != nil {
		return err
	}
	bundle := sourcecoverage.Bundle{
		Manifest:  manifest,
		Inventory: inventory,
	}
	if err := bundle.Validate(); err != nil {
		return err
	}
	if err := bundle.VerifySources(sourceDir); err != nil {
		return err
	}
	if err := bundle.VerifyEvidence(repoDir); err != nil {
		return err
	}
	inventoryBody, err := sourcecoverage.EncodeInventory(inventory)
	if err != nil {
		return err
	}
	reportBody, err := bundle.RenderMarkdown()
	if err != nil {
		return err
	}
	if err := replaceFile(inventoryPath, inventoryBody); err != nil {
		return err
	}
	return replaceFile(reportPath, reportBody)
}

func replaceFile(path string, body []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".source-coverage-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(body); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}
