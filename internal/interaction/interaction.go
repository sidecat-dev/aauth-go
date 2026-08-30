package interaction

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"

	aauth "github.com/aauth-dev/auth-go"
)

const crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// GeneratePendingReference returns an unguessable 16-byte URL-safe reference.
func GeneratePendingReference(random io.Reader) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	value := make([]byte, 16)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

// GenerateCode returns a grouped 40-bit Crockford base32 interaction code.
func GenerateCode(random io.Reader) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	var value [5]byte
	if _, err := io.ReadFull(random, value[:]); err != nil {
		return "", err
	}
	bits := uint64(value[0])<<32 | uint64(value[1])<<24 | uint64(value[2])<<16 | uint64(value[3])<<8 | uint64(value[4])
	code := make([]byte, 9)
	for index := 0; index < 8; index++ {
		if index == 4 {
			code[index] = '-'
		}
		output := index
		if index >= 4 {
			output++
		}
		code[output] = crockfordAlphabet[(bits>>uint(35-5*index))&31]
	}
	return string(code), nil
}

// Digest returns the SHA-256 digest of a normalized interaction code.
func Digest(code string) ([32]byte, error) {
	normalized, err := aauth.NormalizeInteractionCode(code)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256([]byte(normalized)), nil
}
