package aauth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestVerifyPresentedToken(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 3, 22, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personKey := coreTokenKey(t, "person-key")
	accessKey := coreTokenKey(t, "access-key")
	agentKey := coreTokenKey(t, "agent-key")
	otherKey := coreTokenKey(t, "other-key")

	const (
		person   = "https://person.example"
		resource = "https://resource.example"
		access   = "https://access.example"
	)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: person, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}: personKey.PublicJWK(),
		{Issuer: access, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}: accessKey.PublicJWK(),
	}
	agentJKT, err := agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	personClaims := aauth.PersonTokenClaims{
		Issuer: person, DWK: aauth.PersonDiscoveryDocument, Audience: resource,
		Subject: "person-123", Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		JTI: "person-token-1", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}
	authClaims := aauth.AuthTokenClaims{
		Issuer: access, DWK: aauth.AccessDiscoveryDocument, Audience: resource,
		JTI: "auth-token-1", PersonServer: person, Subject: "person-123",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(30 * time.Minute).Unix(), Scope: "read",
	}
	resourceClaims := func(presentedJTI string) aauth.ResourceTokenClaims {
		return aauth.ResourceTokenClaims{
			Issuer: resource, DWK: aauth.ResourceDiscoveryDocument, Audience: person,
			JTI: "resource-token-1", PersonServer: person, Subject: "person-123",
			PresentedJTI: presentedJTI, AgentJKT: agentJKT,
			IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(), Scope: "read",
		}
	}
	mintPerson := func(mutate func(*aauth.PersonTokenClaims)) string {
		t.Helper()
		claims := personClaims
		if mutate != nil {
			mutate(&claims)
		}
		compact, err := aauth.MintPersonToken(personKey, claims)
		if err != nil {
			t.Fatal(err)
		}
		return compact
	}
	mintAuth := func(mutate func(*aauth.AuthTokenClaims)) string {
		t.Helper()
		claims := authClaims
		if mutate != nil {
			mutate(&claims)
		}
		compact, err := aauth.MintAuthToken(accessKey, claims)
		if err != nil {
			t.Fatal(err)
		}
		return compact
	}

	t.Run("person token", func(t *testing.T) {
		presented, err := aauth.VerifyPresentedToken(context.Background(), mintPerson(nil), resourceClaims("person-token-1"), resolver, clock)
		if err != nil {
			t.Fatal(err)
		}
		if presented.Type != aauth.PersonTokenType || presented.Person == nil || presented.Auth != nil ||
			presented.JTI != "person-token-1" || presented.PersonServer != person ||
			!presented.ExpiresAt.Equal(now.Add(time.Hour)) {
			t.Fatalf("presented = %#v", presented)
		}
	})
	t.Run("auth token", func(t *testing.T) {
		presented, err := aauth.VerifyPresentedToken(context.Background(), mintAuth(nil), resourceClaims("auth-token-1"), resolver, clock)
		if err != nil {
			t.Fatal(err)
		}
		if presented.Type != aauth.AuthTokenType || presented.Auth == nil || presented.Person != nil ||
			presented.Issuer != access || presented.PersonServer != person ||
			!presented.ExpiresAt.Equal(now.Add(30*time.Minute)) {
			t.Fatalf("presented = %#v", presented)
		}
	})

	resourceToken, err := aauth.MintResourceToken(coreTokenKey(t, "resource-key"), resourceClaims("person-token-1"))
	if err != nil {
		t.Fatal(err)
	}
	otherResolver := signaturekey.StaticKeyResolver{
		{Issuer: person, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}: otherKey.PublicJWK(),
	}
	refusals := []struct {
		name         string
		compact      string
		presentedJTI string
		resolver     signaturekey.KeyResolver
		mutate       func(*aauth.ResourceTokenClaims)
		want         error
	}{
		{name: "malformed", compact: "not-a-token", presentedJTI: "person-token-1", want: aauth.ErrInvalidPresentedToken},
		{name: "wrong typ", compact: resourceToken, presentedJTI: "person-token-1", want: aauth.ErrInvalidPresentedToken},
		{name: "bad signature", compact: mintPerson(nil), presentedJTI: "person-token-1", resolver: otherResolver, want: aauth.ErrInvalidPresentedToken},
		{
			name: "expired person token",
			compact: mintPerson(func(c *aauth.PersonTokenClaims) {
				c.IssuedAt = now.Add(-2 * time.Hour).Unix()
				c.ExpiresAt = now.Add(-time.Hour).Unix()
			}),
			presentedJTI: "person-token-1", want: aauth.ErrExpiredPresentedToken,
		},
		{
			name: "expired auth token",
			compact: mintAuth(func(c *aauth.AuthTokenClaims) {
				c.IssuedAt = now.Add(-time.Hour).Unix()
				c.ExpiresAt = now.Add(-time.Minute).Unix()
			}),
			presentedJTI: "auth-token-1", want: aauth.ErrExpiredPresentedToken,
		},
		{
			name:         "audience is another resource",
			compact:      mintPerson(func(c *aauth.PersonTokenClaims) { c.Audience = "https://other.example" }),
			presentedJTI: "person-token-1", want: aauth.ErrInvalidPresentedToken,
		},
		{
			name:         "confirmation is another key",
			compact:      mintAuth(func(c *aauth.AuthTokenClaims) { c.Confirmation = aauth.Confirmation{JWK: otherKey.PublicJWK()} }),
			presentedJTI: "auth-token-1", want: aauth.ErrInvalidPresentedToken,
		},
		{name: "jti is not the named token", compact: mintPerson(nil), presentedJTI: "person-token-2", want: aauth.ErrPresentedTokenMismatch},
		{
			name: "auth token names another person server", compact: mintAuth(nil), presentedJTI: "auth-token-1",
			mutate: func(c *aauth.ResourceTokenClaims) { c.PersonServer = "https://other-person.example" },
			want:   aauth.ErrPresentedTokenMismatch,
		},
		{
			name: "subject differs", compact: mintPerson(nil), presentedJTI: "person-token-1",
			mutate: func(c *aauth.ResourceTokenClaims) { c.Subject = "person-456" }, want: aauth.ErrPresentedTokenMismatch,
		},
		{
			name: "mission differs", compact: mintAuth(nil), presentedJTI: "auth-token-1",
			mutate: func(c *aauth.ResourceTokenClaims) { c.MissionS256 = coreTokenS256("mission") }, want: aauth.ErrPresentedTokenMismatch,
		},
		{
			name: "tenant differs", compact: mintPerson(nil), presentedJTI: "person-token-1",
			mutate: func(c *aauth.ResourceTokenClaims) { c.Tenant = "tenant-1" }, want: aauth.ErrPresentedTokenMismatch,
		},
	}
	for _, refusal := range refusals {
		t.Run(refusal.name, func(t *testing.T) {
			claims := resourceClaims(refusal.presentedJTI)
			if refusal.mutate != nil {
				refusal.mutate(&claims)
			}
			keys := refusal.resolver
			if keys == nil {
				keys = resolver
			}
			_, err := aauth.VerifyPresentedToken(context.Background(), refusal.compact, claims, keys, clock)
			if !errors.Is(err, refusal.want) {
				t.Fatalf("error = %v, want %v", err, refusal.want)
			}
			for _, other := range []error{aauth.ErrInvalidPresentedToken, aauth.ErrExpiredPresentedToken, aauth.ErrPresentedTokenMismatch} {
				if other != refusal.want && errors.Is(err, other) {
					t.Fatalf("error = %v also matches %v", err, other)
				}
			}
		})
	}
}
