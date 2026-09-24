package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

const graphScope = "https://graph.microsoft.com/.default"

// Client es un cliente REST mínimo de Microsoft Graph.
type Client struct {
	cred azcore.TokenCredential
	http *http.Client
}

func NewClient(cred azcore.TokenCredential) *Client {
	return &Client{cred: cred, http: &http.Client{Timeout: 30 * time.Second}}
}

// get hace un GET autenticado a Graph y decodifica el JSON en out.
func (c *Client) get(ctx context.Context, path string, out any) error {
	// 🔑 Aquí pedimos el token para GRAPH (no para ARM)
	token, err := c.cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{graphScope}})
	if err != nil {
		return fmt.Errorf("token de graph: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://graph.microsoft.com/v1.0/"+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token.Token)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("graph %s: status %d: %s", path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// GetSignInActivity obtiene la última actividad de sign-in de un usuario.
func (c *Client) GetSignInActivity(ctx context.Context, userID string) (*time.Time, error) {
	var result struct {
		SignInActivity struct {
			LastSignInDateTime *time.Time `json:"lastSignInDateTime"`
		} `json:"signInActivity"`
	}

	err := c.get(ctx, "users/"+url.PathEscape(userID)+"?$select=signInActivity", &result)
	if err != nil {
		return nil, err
	}

	return result.SignInActivity.LastSignInDateTime, nil
}

// GetServicePrincipalSecrets obtiene los secretos de un service principal.
func (c *Client) GetServicePrincipalSecrets(ctx context.Context, spID string) ([]PasswordCredential, error) {
	var result struct {
		PasswordCredentials []PasswordCredential `json:"passwordCredentials"`
	}

	err := c.get(ctx, "servicePrincipals/"+url.PathEscape(spID)+"?$select=passwordCredentials", &result)

	if err != nil {
		return nil, err
	}

	return result.PasswordCredentials, nil
}

// PasswordCredential representa un secreto de app.
type PasswordCredential struct {
	EndDateTime time.Time `json:"endDateTime"`
}

// GetMFAStatus verifica si un usuario tiene MFA registrado.
func (c *Client) GetMFAStatus(ctx context.Context, userID string) (bool, error) {
	var result struct {
		Value []struct {
			IsMFARegistered bool `json:"isMfaRegistered"`
		} `json:"value"`
	}

	// $filter=id eq 'GUID' → nos devuelve solo ese usuario
	filter := url.QueryEscape("id eq '" + userID + "'")
	err := c.get(ctx, "reports/authenticationMethods/userRegistrationDetails?$filter="+filter, &result)
	if err != nil {
		return false, err
	}
	if len(result.Value) == 0 {
		return false, nil // usuario no encontrado en el reporte
	}
	return result.Value[0].IsMFARegistered, nil
}
