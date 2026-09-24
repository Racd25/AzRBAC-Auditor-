package graph

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

// PrincipalInfo es la identidad resuelta.
type PrincipalInfo struct {
	Name string
	Type string // User / Group / ServicePrincipal / Unknown
}

// Resolver traduce objectId → nombre legible.
type Resolver struct {
	client *Client
	cache  map[string]PrincipalInfo
}

func NewResolver(cred azcore.TokenCredential) *Resolver {
	return &Resolver{client: NewClient(cred), cache: map[string]PrincipalInfo{}}
}

// Resolve prueba user → group → servicePrincipal, en orden.
func (r *Resolver) Resolve(ctx context.Context, principalID string) PrincipalInfo {
	if info, ok := r.cache[principalID]; ok {
		return info
	}

	var user struct {
		UserPrincipalName string `json:"userPrincipalName"`
	}
	if err := r.client.get(ctx, "users/"+principalID, &user); err == nil && user.UserPrincipalName != "" {
		return r.store(principalID, PrincipalInfo{Name: user.UserPrincipalName, Type: "User"})
	}

	var group struct {
		DisplayName string `json:"displayName"`
	}
	if err := r.client.get(ctx, "groups/"+principalID, &group); err == nil && group.DisplayName != "" {
		return r.store(principalID, PrincipalInfo{Name: group.DisplayName, Type: "Group"})
	}

	var sp struct {
		DisplayName string `json:"displayName"`
	}
	if err := r.client.get(ctx, "servicePrincipals/"+principalID, &sp); err == nil && sp.DisplayName != "" {
		return r.store(principalID, PrincipalInfo{Name: sp.DisplayName, Type: "ServicePrincipal"})
	}

	return r.store(principalID, PrincipalInfo{Name: principalID, Type: "Unknown"})
}

func (r *Resolver) store(id string, info PrincipalInfo) PrincipalInfo {
	r.cache[id] = info
	return info
}
