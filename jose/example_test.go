package jose_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/aauth-dev/auth-go/jose"
)

func Example() {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	key, err := jose.NewEd25519SigningKey("example-key", privateKey)
	if err != nil {
		panic(err)
	}
	compact, err := jose.SignCompact(
		key,
		jose.Header{Algorithm: jose.Ed25519Algorithm, Type: "example+jwt", KeyID: key.ID()},
		[]byte(`{"subject":"example"}`),
	)
	if err != nil {
		panic(err)
	}
	parsed, err := jose.ParseCompact(compact)
	if err != nil {
		panic(err)
	}
	verified, err := parsed.Verify(key.PublicJWK())
	if err != nil {
		panic(err)
	}
	header, err := verified.Header()
	if err != nil {
		panic(err)
	}
	payload, err := verified.Payload()
	if err != nil {
		panic(err)
	}
	fmt.Println(header.Type)
	fmt.Println(string(payload))
	fmt.Println(header.Type != "" && len(payload) != 0)
	// Output:
	// example+jwt
	// {"subject":"example"}
	// true
}
