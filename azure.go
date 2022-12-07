package azureauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sync"
	"time"

	az "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/coreos/go-oidc"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-cleanhttp"
	azure "github.com/hashicorp/vault-plugin-auth-azure/internal/azure"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/oauth2"
)

var authorizerLifetime = 30 * time.Minute

type computeClient interface {
	Get(ctx context.Context, resourceGroupName string, vmName string, options *armcompute.VirtualMachinesClientGetOptions) (armcompute.VirtualMachinesClientGetResponse, error)
}

type vmssClient interface {
	Get(ctx context.Context, resourceGroupName string, vmScaleSetName string, options *armcompute.VirtualMachineScaleSetsClientGetOptions) (armcompute.VirtualMachineScaleSetsClientGetResponse, error)
}

type msiClient interface {
	Get(ctx context.Context, resourceGroupName string, resourceName string, options *armmsi.UserAssignedIdentitiesClientGetOptions) (armmsi.UserAssignedIdentitiesClientGetResponse, error)
}

type tokenVerifier interface {
	Verify(ctx context.Context, token string) (*oidc.IDToken, error)
}

type provider interface {
	Verifier() tokenVerifier
	ComputeClient(subscriptionID string) (computeClient, error)
	VMSSClient(subscriptionID string) (vmssClient, error)
	MSIClient(subscriptionID string) (msiClient, error)
}

type azureProvider struct {
	oidcVerifier         *oidc.IDTokenVerifier
	settings             *azureSettings
	httpClient           *http.Client
	authorizerExpiration time.Time
	lock                 sync.RWMutex
}

type oidcDiscoveryInfo struct {
	Issuer  string `json:"issuer"`
	JWKSURL string `json:"jwks_uri"`
}

func (b *azureAuthBackend) newAzureProvider(ctx context.Context, config *azureConfig) (*azureProvider, error) {
	httpClient := cleanhttp.DefaultClient()
	settings, err := b.getAzureSettings(ctx, config)
	if err != nil {
		return nil, err
	}

	// In many OIDC providers, the discovery endpoint matches the issuer. For Azure AD, the discovery
	// endpoint is the AD endpoint which does not match the issuer defined in the discovery payload. This
	// makes a request to the discovery URL to determine the issuer and key set information to configure
	// the OIDC verifier
	discoveryURL := fmt.Sprintf("%s%s/.well-known/openid-configuration", settings.Environment.ActiveDirectoryEndpoint, settings.TenantID)
	req, err := http.NewRequestWithContext(ctx, "GET", discoveryURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent(settings.PluginEnv))

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errwrap.Wrapf("unable to read response body: {{err}}", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", resp.Status, body)
	}
	var discoveryInfo oidcDiscoveryInfo
	if err := json.Unmarshal(body, &discoveryInfo); err != nil {
		return nil, errwrap.Wrapf("unable to unmarshal discovery url: {{err}}", err)
	}

	// Create a remote key set from the discovery endpoint
	keySetCtx := context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)
	remoteKeySet := oidc.NewRemoteKeySet(keySetCtx, discoveryInfo.JWKSURL)

	verifierConfig := &oidc.Config{
		ClientID:             settings.Resource,
		SupportedSigningAlgs: []string{oidc.RS256},
	}
	oidcVerifier := oidc.NewVerifier(discoveryInfo.Issuer, remoteKeySet, verifierConfig)

	return &azureProvider{
		settings:     settings,
		oidcVerifier: oidcVerifier,
		httpClient:   httpClient,
	}, nil
}

func (p *azureProvider) Verifier() tokenVerifier {
	return p.oidcVerifier
}

func (p *azureProvider) ComputeClient(subscriptionID string) (computeClient, error) {
	cred, err := az.NewClientSecretCredential(p.settings.TenantID, p.settings.ClientID, p.settings.ClientSecret, nil)
	if err != nil {
		return nil, err
	}

	client, err := armcompute.NewVirtualMachinesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}

	// client := compute.NewVirtualMachinesClientWithBaseURI(p.settings.Environment.ResourceManagerEndpoint, subscriptionID)
	// client.Sender = p.httpClient
	// client.AddToUserAgent(userAgent(p.settings.PluginEnv))
	return client, nil
}

func (p *azureProvider) VMSSClient(subscriptionID string) (vmssClient, error) {

	cred, err := az.NewClientSecretCredential(p.settings.TenantID, p.settings.ClientID, p.settings.ClientSecret, nil)
	if err != nil {
		return nil, err
	}

	client, err := armcompute.NewVirtualMachineScaleSetsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}

	// client := compute.NewVirtualMachineScaleSetsClientWithBaseURI(p.settings.Environment.ResourceManagerEndpoint, subscriptionID)
	// client.Sender = p.httpClient
	// client.AddToUserAgent(userAgent(p.settings.PluginEnv))
	return client, nil
}

func (p *azureProvider) MSIClient(subscriptionID string) (msiClient, error) {

	cred, err := az.NewManagedIdentityCredential(nil)
	if err != nil {
		return nil, err
	}

	client, err := armmsi.NewUserAssignedIdentitiesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}

	// client.Sender = p.httpClient
	// client.AddToUserAgent(userAgent(p.settings.PluginEnv))
	return client, nil
}

type azureSettings struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	Environment  azure.Environment
	Resource     string
	PluginEnv    *logical.PluginEnvironment
}

func (b *azureAuthBackend) getAzureSettings(ctx context.Context, config *azureConfig) (*azureSettings, error) {
	settings := new(azureSettings)

	envTenantID := os.Getenv("AZURE_TENANT_ID")
	switch {
	case envTenantID != "":
		settings.TenantID = envTenantID
	case config.TenantID != "":
		settings.TenantID = config.TenantID
	default:
		return nil, errors.New("tenant_id is required")
	}

	envResource := os.Getenv("AZURE_AD_RESOURCE")
	switch {
	case envResource != "":
		settings.Resource = envResource
	case config.Resource != "":
		settings.Resource = config.Resource
	default:
		return nil, errors.New("resource is required")
	}

	clientID := os.Getenv("AZURE_CLIENT_ID")
	if clientID == "" {
		clientID = config.ClientID
	}
	settings.ClientID = clientID

	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")
	if clientSecret == "" {
		clientSecret = config.ClientSecret
	}
	settings.ClientSecret = clientSecret

	envName := os.Getenv("AZURE_ENVIRONMENT")
	if envName == "" {
		envName = config.Environment
	}
	if envName == "" {
		settings.Environment = azure.PublicCloud
	} else {
		var err error
		settings.Environment, err = azure.EnvironmentFromName(envName)
		if err != nil {
			return nil, err
		}
	}

	pluginEnv, err := b.System().PluginEnv(ctx)
	if err != nil {
		return nil, fmt.Errorf("error loading plugin environment: %w", err)
	}
	settings.PluginEnv = pluginEnv

	return settings, nil
}
