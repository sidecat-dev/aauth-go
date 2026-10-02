package personserver

import (
	"io"
	"net/http"
)

// requestBodyIsEmpty checks content rather than the identity of Go's body
// reader: an empty HTTP/2 request can have a non-nil reader other than NoBody.
// Read at most one byte; a payload or read error makes the request nonempty.
func requestBodyIsEmpty(request *http.Request) bool {
	if request.ContentLength > 0 {
		return false
	}
	if request.Body == nil || request.Body == http.NoBody {
		return true
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, 1))
	return err == nil && len(body) == 0
}
