package events

import (
	"crypto/sha256"
)

// DeliveryFingerprint is a local exact-replay identity. It is not a wire
// claim and does not attempt to identify a business-level event.
type DeliveryFingerprint [sha256.Size]byte

// Fingerprint derives SHA-256(exact compact token || 0x00 || exact content
// type || 0x00 || exact payload). EventID identifies the subscription and
// therefore cannot safely identify a delivery when one subscription accepts
// more than one event.
func Fingerprint(exactEventToken, exactContentType string, exactPayload []byte) DeliveryFingerprint {
	digest := sha256.New()
	_, _ = digest.Write([]byte(exactEventToken))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(exactContentType))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(exactPayload)
	var fingerprint DeliveryFingerprint
	copy(fingerprint[:], digest.Sum(nil))
	return fingerprint
}
