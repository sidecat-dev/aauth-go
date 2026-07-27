package sourcecoverage

import _ "embed"

var (
	//go:embed source-coverage.json
	embeddedManifest []byte

	//go:embed source-section-inventory.json
	embeddedInventory []byte
)

// Embedded returns the maintained source-coverage contract shipped with this
// module. Load validates the embedded JSON before it reaches callers.
func Embedded() (Bundle, error) {
	return Load(embeddedManifest, embeddedInventory)
}
