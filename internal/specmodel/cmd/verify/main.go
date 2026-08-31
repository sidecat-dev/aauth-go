// Command verify checks the protocol model against an exact editor-source
// directory. It is a maintainer tool, not an AAuth protocol endpoint.
package main

import (
	"flag"
	"fmt"
	"os"

	"gitlab.com/sidecat-dev/aauth-go/internal/specmodel"
)

func main() {
	sourceDirectory := flag.String("source-dir", "", "directory containing the pinned editor-source Markdown files")
	flag.Parse()
	if *sourceDirectory == "" {
		fmt.Fprintln(os.Stderr, "verify: -source-dir is required")
		os.Exit(2)
	}
	model, err := specmodel.Load()
	if err == nil {
		err = specmodel.VerifySourceDirectory(model, *sourceDirectory)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify:", err)
		os.Exit(1)
	}
	fmt.Printf("verified %d sources, %d headings, and %d requirement occurrences\n", len(model.Sources), len(model.Headings), len(model.Requirements))
}
