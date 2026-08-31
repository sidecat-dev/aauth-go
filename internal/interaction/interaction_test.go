package interaction_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/interaction"
)

func TestGeneratePendingReference(t *testing.T) {
	t.Parallel()

	reference, err := interaction.GeneratePendingReference(bytes.NewReader([]byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if reference != "AAECAwQFBgcICQoLDA0ODw" {
		t.Fatalf("reference = %q", reference)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(reference)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 16 {
		t.Fatalf("reference decoded length = %d", len(decoded))
	}
}

func TestGenerateCode(t *testing.T) {
	t.Parallel()

	code, err := interaction.GenerateCode(bytes.NewReader([]byte{0, 1, 2, 3, 4}))
	if err != nil {
		t.Fatal(err)
	}
	if code != "000G-40R4" {
		t.Fatalf("code = %q", code)
	}
}

func TestGenerateUsesDefaultRandomReader(t *testing.T) {
	t.Parallel()

	if _, err := interaction.GeneratePendingReference(nil); err != nil {
		t.Fatalf("GeneratePendingReference(nil): %v", err)
	}
	if _, err := interaction.GenerateCode(nil); err != nil {
		t.Fatalf("GenerateCode(nil): %v", err)
	}
}

func TestDigestNormalizesHumanInput(t *testing.T) {
	t.Parallel()

	digest, err := interaction.Digest("aiB2-o3d4")
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte("A1B203D4"))
	if digest != want {
		t.Fatalf("digest = %x, want %x", digest, want)
	}
	if _, err := interaction.Digest("short"); err == nil {
		t.Fatal("Digest(short) succeeded")
	}
	if normalized, err := aauth.NormalizeInteractionCode("aiB2-o3d4"); err != nil || normalized != "A1B203D4" {
		t.Fatalf("normalization = %q, %v", normalized, err)
	}
}
