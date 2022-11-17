package azureauth

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathRotateRoot(b *azureAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: "rotate-root",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback:                    b.pathRotateRoot,
				ForwardPerformanceSecondary: true,
				ForwardPerformanceStandby:   true,
			},
		},

		HelpSynopsis: "Attempt to rotate the root credentials used to communicate with Azure.",
		HelpDescription: "This path will attempt to generate new root credentials for the user used to access and manipulate Azure.\n" +
			"The new credentials will not be returned from this endpoint, nor the read config endpoint.",
	}
}

func (b *azureAuthBackend) pathRotateRoot(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, fmt.Errorf("config is nil")
	}

	expDur := config.RootPasswordTTL
	if expDur == 0 {
		expDur = defaultRootPasswordTTL
	}
	expiration := time.Now().Add(expDur)

	provider, err := b.getProvider(ctx, config)
	if err != nil {
		return nil, err
	}

	client := provider.GetClient()
	// We need to use List instead of Get here because we don't have the Object ID
	// (which is different from the Application/Client ID)
	apps, err := client.ListApplications(ctx, fmt.Sprintf("appId eq '%s'", config.ClientID))
	if err != nil {
		return nil, err
	}

	if len(apps) == 0 {
		return nil, fmt.Errorf("no application found")
	}
	if len(apps) > 1 {
		return nil, fmt.Errorf("multiple applications found - double check your client_id")
	}

	app := apps[0]

	uniqueID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate UUID: %w", err)
	}

	// This could have the same username customization logic put on it if we really wanted it here
	passwordDisplayName := fmt.Sprintf("vault-%s", uniqueID)
	newPasswordResp, err := client.AddApplicationPassword(ctx, *app.ID, passwordDisplayName, expiration)
	if err != nil {
		return nil, fmt.Errorf("failed to add new password: %w", err)
	}

	var wal walRotateRoot
	walID, walErr := framework.PutWAL(ctx, req.Storage, walRotateRootCreds, wal)
	if walErr != nil {
		err = client.RemoveApplicationPassword(ctx, *app.ID, *newPasswordResp.PasswordCredential.KeyID)
		merr := multierror.Append(err, err)
		return &logical.Response{}, merr
	}

	config.NewClientSecret = *newPasswordResp.SecretText
	config.NewClientSecretCreated = time.Now()
	config.NewClientSecretExpirationDate = newPasswordResp.EndDate.Time
	config.NewClientSecretKeyID = *newPasswordResp.KeyID

	err = b.saveConfig(ctx, config, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to save new configuration: %w", err)
	}

	b.updatePassword = true

	err = framework.DeleteWAL(ctx, req.Storage, walID)
	if err != nil {
		b.Logger().Error("rotate root", "delete wal", err)
	}

	return nil, err
}

type passwordRemover interface {
	RemoveApplicationPassword(ctx context.Context, applicationObjectID string, keyID string) error
}

func removeApplicationPasswords(ctx context.Context, passRemover passwordRemover, appID string, passwordKeyIDs ...string) (err error) {
	merr := new(multierror.Error)
	for _, keyID := range passwordKeyIDs {
		// Attempt to remove all of them, don't fail early
		err := passRemover.RemoveApplicationPassword(ctx, appID, keyID)
		if err != nil {
			merr = multierror.Append(merr, err)
		}
	}

	return merr.ErrorOrNil()
}

func intersectStrings(a []string, b []string) []string {
	if len(a) == 0 || len(b) == 0 {
		return []string{}
	}

	aMap := map[string]struct{}{}
	for _, aStr := range a {
		aMap[aStr] = struct{}{}
	}

	result := []string{}
	for _, bStr := range b {
		if _, exists := aMap[bStr]; exists {
			result = append(result, bStr)
		}
	}
	return result
}
