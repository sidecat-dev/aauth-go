// Command generate refreshes requirement occurrences after the heading map and
// exact editor sources have been reviewed. It never invents ownership: each
// occurrence inherits its checked heading's owners and proof seam.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"aauth-go/internal/specmodel"
)

func main() {
	sourceDirectory := flag.String("source-dir", "", "directory containing the pinned editor-source Markdown files")
	output := flag.String("output", "", "model JSON path to replace atomically")
	flag.Parse()
	if *sourceDirectory == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "generate: -source-dir and -output are required")
		os.Exit(2)
	}
	model, err := specmodel.Load()
	if err == nil {
		model.Requirements, err = specmodel.ExtractRequirements(model, *sourceDirectory)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate:", err)
		os.Exit(1)
	}
	data, err := json.MarshalIndent(model, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate:", err)
		os.Exit(1)
	}
	data = append(data, '\n')
	temporary := *output + ".tmp"
	if err := os.WriteFile(temporary, data, 0o644); err == nil {
		err = os.Rename(temporary, *output)
	}
	if err != nil {
		_ = os.Remove(temporary)
		fmt.Fprintln(os.Stderr, "generate:", err)
		os.Exit(1)
	}
	absolute, _ := filepath.Abs(*output)
	fmt.Printf("wrote %d requirement occurrences to %s\n", len(model.Requirements), absolute)
}
