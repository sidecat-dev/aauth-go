package aauth

import (
	"encoding/json"
	"fmt"
)

type tokenProfileSet uint8

const (
	agentTokenProfile tokenProfileSet = 1 << iota
	personTokenProfile
	resourceTokenProfile
	authTokenProfile
)

type coreAuthorizationMemberRule struct {
	name             string
	profiles         tokenProfileSet
	resourceRequires []string
	authRequires     []string
}

var coreAuthorizationMemberCatalog = [...]coreAuthorizationMemberRule{
	{
		name:             "r3_uri",
		profiles:         resourceTokenProfile | authTokenProfile,
		resourceRequires: []string{"r3_s256"},
		authRequires:     []string{"r3_s256", "r3_granted"},
	},
	{
		name:             "r3_s256",
		profiles:         resourceTokenProfile | authTokenProfile,
		resourceRequires: []string{"r3_uri"},
		authRequires:     []string{"r3_uri", "r3_granted"},
	},
	{
		name:         "r3_granted",
		profiles:     authTokenProfile,
		authRequires: []string{"r3_uri", "r3_s256"},
	},
	{
		name:         "r3_per_call",
		profiles:     authTokenProfile,
		authRequires: []string{"r3_uri", "r3_s256", "r3_granted"},
	},
	{
		name:     "budget",
		profiles: resourceTokenProfile | authTokenProfile,
	},
	{
		name:             "budget_consumed",
		profiles:         resourceTokenProfile,
		resourceRequires: []string{"budget"},
	},
}

var obsoleteAuthorizationMembers = [...]string{"r3_conditional"}

func tokenProfile(tokenType string) tokenProfileSet {
	switch tokenType {
	case AgentTokenType:
		return agentTokenProfile
	case PersonTokenType:
		return personTokenProfile
	case ResourceTokenType:
		return resourceTokenProfile
	case AuthTokenType:
		return authTokenProfile
	default:
		return 0
	}
}

// inspectCoreAuthorizationMembers returns defensive exact values only after
// every recognized current member is applicable to the token profile and its
// required companion members are present.
func inspectCoreAuthorizationMembers(
	members map[string]json.RawMessage,
	tokenType string,
) (map[string]json.RawMessage, error) {
	profile := tokenProfile(tokenType)
	if profile == 0 {
		return nil, fmt.Errorf("aauth: unknown Core token type %q", tokenType)
	}
	for _, name := range obsoleteAuthorizationMembers {
		if _, present := members[name]; present {
			return nil, &unsupportedTokenClaimError{
				tokenType: tokenType,
				claim:     name,
				reason:    "the claim was removed from the current specification",
			}
		}
	}
	recognized := make(map[string]json.RawMessage)
	for _, rule := range coreAuthorizationMemberCatalog {
		raw, present := members[rule.name]
		if !present {
			continue
		}
		if rule.profiles&profile == 0 {
			return nil, &unsupportedTokenClaimError{
				tokenType: tokenType,
				claim:     rule.name,
				reason:    "the claim is not applicable to this token profile",
			}
		}
		var required []string
		switch profile {
		case resourceTokenProfile:
			required = rule.resourceRequires
		case authTokenProfile:
			required = rule.authRequires
		}
		for _, companion := range required {
			if _, present := members[companion]; !present {
				return nil, &unsupportedTokenClaimError{
					tokenType: tokenType,
					claim:     rule.name,
					reason:    "the claim requires " + companion,
				}
			}
		}
		recognized[rule.name] = append(json.RawMessage(nil), raw...)
	}
	return recognized, nil
}

func validateAuthorizationMembers(payload []byte, tokenType string) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(payload, &members); err != nil {
		return fmt.Errorf("aauth: decode %s claims: %w", tokenType, err)
	}
	_, err := inspectCoreAuthorizationMembers(members, tokenType)
	return err
}
