package aauth

import "time"

// RateLimitedError is a recipient's definite 429 rate_limited refusal of a
// revocation request together with its required Retry-After feedback. It is
// returned only when the recipient supplied exactly one valid Retry-After;
// otherwise the plain *ProblemError is returned and no delay is implied.
// RetryAfter is the delay as supplied (zero when an HTTP-date is not in the
// future). The caller decides whether and when to repeat the request.
type RateLimitedError struct {
	Problem    *ProblemError
	RetryAfter time.Duration
}

func (failure *RateLimitedError) Error() string {
	if failure == nil || failure.Problem == nil {
		return "aauth: rate limited"
	}
	return failure.Problem.Error() + " (retry after " + failure.RetryAfter.String() + ")"
}

// Unwrap returns the underlying problem so errors.As finds *ProblemError.
func (failure *RateLimitedError) Unwrap() error {
	if failure == nil || failure.Problem == nil {
		return nil
	}
	return failure.Problem
}
