package aauth

import "gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"

func rejectDuplicateJSONNames(value []byte) error {
	return jsonstrict.RejectAmbiguousNames(value)
}
