package api

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	az "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/google/uuid"
	abstractions "github.com/microsoft/kiota-abstractions-go"
	kiota "github.com/microsoft/kiota-authentication-azure-go"

	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	graphconfig "github.com/microsoftgraph/msgraph-sdk-go/applications"
	graphmodels "github.com/microsoftgraph/msgraph-sdk-go/models"
)

var _ MSGraphClient = (*AppClient)(nil)

type AppClient struct {
	client   *msgraphsdk.GraphServiceClient
	settings ClientSettings
}

type ClientSettings struct {
	ClientID     string
	ClientSecret string
	TenantID     string
}

// NewMSGraphApplicationClient creates a new MS Graph Client
// to allow interaction with the MS Graph v1.0 API.
func NewMSGraphApplicationClient(settings ClientSettings) (*AppClient, error) {
	var cred azcore.TokenCredential
	var err error
	if settings.ClientSecret != "" {
		cred, err = az.NewClientSecretCredential(settings.TenantID, settings.ClientID, settings.ClientSecret, nil)
		if err != nil {
			return nil, err
		}
	} else {
		cred, err = az.NewManagedIdentityCredential(nil)
		if err != nil {
			return nil, err
		}

	}

	provider, err := kiota.NewAzureIdentityAuthenticationProvider(cred)
	if err != nil {
		fmt.Printf("Error authentication provider: %v\n", err)
		return nil, err
	}
	requestAdapter, err := msgraphsdk.NewGraphRequestAdapter(provider)
	if err != nil {
		return nil, err
	}
	client := msgraphsdk.NewGraphServiceClient(requestAdapter)

	ac := &AppClient{
		client:   client,
		settings: settings,
	}

	return ac, nil
}

func GetAzureTokenCredential(c *AppClient) (azcore.TokenCredential, error) {
	var cred azcore.TokenCredential
	var err error
	if c.settings.ClientSecret != "" {
		cred, err = az.NewClientSecretCredential(c.settings.TenantID, c.settings.ClientID, c.settings.ClientSecret, nil)
		if err != nil {
			return nil, err
		}
	} else {
		cred, err = az.NewManagedIdentityCredential(nil)
		if err != nil {
			return nil, err
		}

	}

	return cred, nil
}

// ListApplications lists all Azure application in organization based on a filter.
func (c *AppClient) ListApplications(ctx context.Context, filter string) ([]graphmodels.Applicationable, error) {
	cred, err := GetAzureTokenCredential(c)
	if err != nil {
		return nil, fmt.Errorf("error getting token credential: err=%s", err)
	}

	scope := fmt.Sprintf("%s/.default", c.settings.ClientID)
	opts := policy.TokenRequestOptions{
		Scopes: []string{scope},
	}
	token, err := cred.GetToken(ctx, opts)
	if err != nil {
		return nil, err
	}

	headers := abstractions.NewRequestHeaders()
	headers.Add("Content-type", "application/json")
	headers.Add("Authorization", fmt.Sprintf("Bearer %s", token.Token))
	headers.Add("ConsistencyLevel", "eventual")

	requestParameters := &graphconfig.ApplicationsRequestBuilderGetQueryParameters{
		Filter: &filter,
		//Orderby: []string{"displayName"},
	}

	configuration := &graphconfig.ApplicationsRequestBuilderGetRequestConfiguration{
		Headers:         headers,
		QueryParameters: requestParameters,
	}

	result, err := c.client.Applications().Get(ctx, configuration)
	if err != nil {
		return nil, err
	}

	return result.GetValue(), nil
}

// AddApplicationPassword adds an Azure application password.
func (c *AppClient) AddApplicationPassword(ctx context.Context, applicationObjectID string, displayName string, endDateTime time.Time) (graphmodels.PasswordCredentialable, error) {
	passwordCredential := graphmodels.NewPasswordCredential()
	passwordCredential.SetDisplayName(&displayName)
	passwordCredential.SetEndDateTime(&endDateTime)
	requestBody := graphconfig.NewItemAddPasswordPostRequestBody()
	requestBody.SetPasswordCredential(passwordCredential)

	result, err := c.client.ApplicationsById(applicationObjectID).AddPassword().Post(ctx, requestBody, nil)
	if err != nil {
		return result, err
	}

	return result, nil
}

// RemoveApplicationPassword removes an Azure application password.
func (c *AppClient) RemoveApplicationPassword(ctx context.Context, applicationObjectID string, keyID *uuid.UUID) error {
	requestBody := graphconfig.NewItemRemovePasswordPostRequestBody()
	requestBody.SetKeyId(keyID)

	c.client.ApplicationsById(applicationObjectID).RemovePassword().Post(ctx, requestBody, nil)

	return nil
}

// DeleteApplication deletes an Azure application object.
func (c *AppClient) DeleteApplication(ctx context.Context, applicationObjectID string) error {
	return c.client.ApplicationsById(applicationObjectID).Delete(ctx, nil)
}
