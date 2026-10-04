package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func call(ctx context.Context, state string, config configuration) error {
	transport, err := httpClient(state, config)
	if err != nil {
		return err
	}
	keys, err := resolver(transport)
	if err != nil {
		return err
	}
	proof, err := signingKey(state, "agent-proof")
	if err != nil {
		return err
	}
	original, err := clientagent.New(ctx, clientagent.Config{Identifier: agentID, SigningKey: proof, AgentToken: config.AgentToken, KeyResolver: keys, HTTPClient: transport, Clock: clock})
	if err != nil {
		return err
	}
	result, err := original.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: personOrigin, Resource: ordersOrigin})
	if err != nil {
		return err
	}
	person, ok := result.Token()
	if !ok {
		return errors.New("demo requires immediate person authorization")
	}
	challenge, err := original.Authorize(ctx, clientagent.AuthorizeRequest{Resource: ordersOrigin, PersonToken: person, Scopes: []string{ordersScope}})
	if err != nil {
		return err
	}
	auth, err := original.Exchange(ctx, clientagent.ExchangeRequest{PersonServer: personOrigin, ResourceToken: challenge, PresentedToken: person})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, ordersOrigin+"/orders/42/fulfill", nil)
	if err != nil {
		return err
	}
	response, err := original.Do(ctx, clientagent.Call{Request: request, AuthToken: auth})
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return responseError(response)
	}
	var output chainResult
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&output); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(state, "last-upstream.jwt"), []byte(auth), 0600); err != nil {
		return err
	}
	return outputJSON(output)
}

func callInventory(ctx context.Context, relay *clientagent.Client, upstream string, keys signaturekey.KeyResolver) (chainResult, error) {
	var output chainResult
	result, err := relay.PersonToken(ctx, clientagent.PersonTokenRequest{Resource: inventoryOrigin, UpstreamToken: upstream})
	if err != nil {
		return output, err
	}
	person, ok := result.Token()
	if !ok {
		return output, errors.New("call-chain interaction is outside this profile")
	}
	personClaims, err := aauth.VerifyPersonToken(ctx, person, keys, clock)
	if err != nil {
		return output, err
	}
	challenge, err := relay.Authorize(ctx, clientagent.AuthorizeRequest{Resource: inventoryOrigin, PersonToken: person, Scopes: []string{inventoryScope}, UpstreamToken: upstream})
	if err != nil {
		return output, err
	}
	auth, err := relay.Exchange(ctx, clientagent.ExchangeRequest{ResourceToken: challenge, PresentedToken: person, UpstreamToken: upstream})
	if err != nil {
		return output, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, inventoryOrigin+"/inventory/42/reserve", nil)
	if err != nil {
		return output, err
	}
	response, err := relay.Do(ctx, clientagent.Call{Request: request, AuthToken: auth, UpstreamToken: upstream})
	if err != nil {
		return output, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return output, responseError(response)
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&output); err != nil {
		return output, err
	}
	output.PersonExp = personClaims.ExpiresAt
	return output, nil
}

func responseError(response *http.Response) error {
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		return err
	}
	return fmt.Errorf("peer returned HTTP %d: %s", response.StatusCode, body)
}

func status(ctx context.Context, state string, config configuration) (map[string]any, error) {
	client, err := httpClient(state, config)
	if err != nil {
		return nil, err
	}
	result := make(map[string]any)
	for _, role := range roles {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, origins[role]+"/status", nil)
		if err != nil {
			return nil, err
		}
		response, err := client.Do(request)
		if err != nil {
			return nil, err
		}
		var observed map[string]any
		decode := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&observed)
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s status HTTP %d", role, response.StatusCode)
		}
		if decode != nil {
			return nil, decode
		}
		result[role] = observed
		if role == "inventory" {
			result["consequence_count"] = observed["consequence_count"]
		}
	}
	return result, nil
}

func probe(ctx context.Context, state string, config configuration, kind string) error {
	if kind != "unsigned" && kind != "expired" {
		return errors.New("--kind must be unsigned or expired")
	}
	client, err := httpClient(state, config)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, ordersOrigin+"/orders/42/fulfill", nil)
	if err != nil {
		return err
	}
	if kind == "expired" {
		encoded, err := os.ReadFile(filepath.Join(state, "last-upstream.jwt"))
		if err != nil {
			return err
		}
		keys, err := resolver(client)
		if err != nil {
			return err
		}
		_, err = aauth.VerifyAuthToken(ctx, string(encoded), keys, clock)
		// Proceed only when this exact previously issued credential is expired.
		var failure *aauth.TokenValidationError
		if !errors.As(err, &failure) || failure.Code != aauth.TokenValidationExpired {
			return errors.New("retained upstream credential has not expired; wait until upstream_exp plus one second")
		}
		proof, err := signingKey(state, "agent-proof")
		if err != nil {
			return err
		}
		if err := signaturekey.SignJWTRequest(request, proof, string(encoded), clock); err != nil {
			return err
		}
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	// A probe never retries a refused or uncertain application request.
	if response.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("probe was not refused: HTTP %d", response.StatusCode)
	}
	return outputJSON(map[string]any{"status": "refused", "kind": kind, "http_status": response.StatusCode, "signature_error": response.Header.Get("Signature-Error"), "observed_at": time.Now().UTC().Format(time.RFC3339)})
}
