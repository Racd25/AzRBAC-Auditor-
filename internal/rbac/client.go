package rbac

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

// RoleAssignment representa una asignación de rol simplificada.
type RoleAssignment struct {
	ID               string
	PrincipalID      string
	PrincipalType    string
	RoleDefinitionID string
	Scope            string
}

// Client es el cliente para consultar RBAC de Azure.
type Client struct {
	client *armauthorization.RoleAssignmentsClient
}

// NewClient crea un nuevo cliente RBAC.
func NewClient(cred azcore.TokenCredential, subscriptionID string) (*Client, error) {
	client, err := armauthorization.NewRoleAssignmentsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("error creando cliente RBAC: %w", err)
	}
	return &Client{client: client}, nil
}

// ListAll lista todas las asignaciones de roles en la suscripción.
func (c *Client) ListAll(ctx context.Context) ([]RoleAssignment, error) {
	var assignments []RoleAssignment

	pager := c.client.NewListForSubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("error listando asignaciones: %w", err)
		}
		for _, ra := range page.Value {
			assignment := RoleAssignment{
				ID:               *ra.ID,
				RoleDefinitionID: *ra.Properties.RoleDefinitionID,
				Scope:            *ra.Properties.Scope,
			}
			if ra.Properties.PrincipalID != nil {
				assignment.PrincipalID = *ra.Properties.PrincipalID
			}
			if ra.Properties.PrincipalType != nil {
				assignment.PrincipalType = string(*ra.Properties.PrincipalType)
			}
			assignments = append(assignments, assignment)
		}
	}

	return assignments, nil
}