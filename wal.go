package azureauth

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
)

const (
	walAppKey          = "appCreate"
	walRotateRootCreds = "rotateRootCreds"
)

// Eventually expire the WAL if for some reason the rollback operation consistently fails
var maxWALAge = 24 * time.Hour

func (b *azureAuthBackend) walRollback(ctx context.Context, req *logical.Request, kind string, data interface{}) error {
	switch kind {
	case walAppKey:
		return b.rollbackAppWAL(ctx, req, data)
	case walRotateRootCreds:
		return b.rollbackRootWAL(ctx, req, data)
	default:
		return fmt.Errorf("unknown rollback type %q", kind)
	}
}

type walApp struct {
	AppID      string
	AppObjID   string
	Expiration time.Time
}

func (b *azureAuthBackend) rollbackAppWAL(ctx context.Context, req *logical.Request, data interface{}) error {
	// Decode the WAL data
	var entry walApp
	d, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.StringToTimeHookFunc(time.RFC3339),
		Result:     &entry,
	})
	if err != nil {
		return err
	}
	err = d.Decode(data)
	if err != nil {
		return err
	}

	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return err
	}
	provider, err := b.getProvider(ctx, config)
	if err != nil {
		return err
	}

	b.Logger().Debug("rolling back SP", "appID", entry.AppID, "appObjID", entry.AppObjID)

	client, err := provider.MSGraphClient(config.SubscriptionID)
	if err != nil {
		return err
	}
	// Attempt to delete the App. deleteApp doesn't return an error if the app isn't
	// found, so no special handling is needed for that case. If we don't succeed within
	// maxWALAge (e.g. client creds have changed and the delete will never succeed),
	// unconditionally remove the WAL.
	if err := client.DeleteApplication(ctx, entry.AppObjID); err != nil {
		b.Logger().Warn("rollback error deleting App", "err", err)

		if time.Now().After(entry.Expiration) {
			return nil
		}
		return err
	}

	return nil
}

type walRotateRoot struct{}

func (b *azureAuthBackend) rollbackRootWAL(ctx context.Context, req *logical.Request, data interface{}) error {
	b.Logger().Debug("rolling back config")
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return err
	}

	config.NewClientSecret = ""
	config.NewClientSecretCreated = time.Time{}
	config.NewClientSecretExpirationDate = time.Time{}
	config.NewClientSecretKeyID = ""

	err = b.saveConfig(ctx, config, req.Storage)
	if err != nil {
		return err
	}

	b.updatePassword = false

	return nil
}
