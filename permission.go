package aauth

import "fmt"

// Permission is a decision returned by an AAuth permission endpoint.
type Permission string

const (
	PermissionGranted Permission = "granted"
	PermissionDenied  Permission = "denied"
)

// ParsePermission validates a permission decision.
func ParsePermission(value string) (Permission, error) {
	permission := Permission(value)
	switch permission {
	case PermissionGranted, PermissionDenied:
		return permission, nil
	default:
		return "", fmt.Errorf("aauth: unsupported permission %q", value)
	}
}
