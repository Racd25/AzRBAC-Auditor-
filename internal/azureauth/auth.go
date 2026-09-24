package azureauth

import (
	//"context"
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// Credentials contiene las credenciales autenticadas de Azure.
type Credentials struct {
	azidentity.DefaultAzureCredential
}

// NewCredentials crea credenciales usando las variables de entorno.
func NewCredentials() (*Credentials, error) {
	// azidentity lee automáticamente:
	// AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("no se pudo autenticar: %w", err)
	}
	return &Credentials{*cred}, nil
}

// GetSubscriptionID lee el ID de suscripción desde variables de entorno.
func GetSubscriptionID() (string, error) {
	subID := os.Getenv("AZURE_SUBSCRIPTION_ID")
	if subID == "" {
		return "", fmt.Errorf("AZURE_SUBSCRIPTION_ID no está configurado")
	}
	return subID, nil
}
