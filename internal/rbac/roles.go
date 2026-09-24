package rbac

import (
	"context"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
)

// GUIDs de roles built-in (fallback si la API no responde)
var builtInRoles = map[string]string{
	"8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
	"b24988ac-6180-42a0-ab88-20664c394456": "Contributor",
	"acdd72a7-3385-48ef-bd42-f606fba81ae7": "Reader",
	"18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
	"9980e02c-c2be-4d73-94e8-173b1dc7cf3c": "Virtual Machine Contributor",
}

// RoleResolver traduce roleDefinitionId → nombre legible, con caché.
type RoleResolver struct {
	client *armauthorization.RoleDefinitionsClient
	cache  map[string]string
	mu     sync.Mutex
}

func NewRoleResolver(cred azcore.TokenCredential, subscriptionID string) (*RoleResolver, error) {
	client, err := armauthorization.NewRoleDefinitionsClient(cred, nil)
	if err != nil {
		return nil, err
	}
	return &RoleResolver{client: client, cache: map[string]string{}}, nil
}

// RoleName resuelve el nombre del rol.
func (r *RoleResolver) RoleName(ctx context.Context, roleDefinitionID string) string {
	// Extrae el GUID final del ID largo
	guid := roleDefinitionID
	if idx := strings.LastIndex(roleDefinitionID, "/"); idx >= 0 {
		guid = roleDefinitionID[idx+1:]
	}

	// 1) Caché
	r.mu.Lock()
	if name, ok := r.cache[guid]; ok {
		r.mu.Unlock()
		return name
	}
	r.mu.Unlock()

	// 2) API de Azure
	resp, err := r.client.GetByID(ctx, roleDefinitionID, nil)
	if err == nil && resp.Properties != nil && resp.Properties.RoleName != nil {
		name := *resp.Properties.RoleName
		r.mu.Lock()
		r.cache[guid] = name
		r.mu.Unlock()
		return name
	}

	// 3) Fallback local
	if name, ok := builtInRoles[guid]; ok {
		return name
	}
	return guid
}
