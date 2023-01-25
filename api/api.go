package api

import (
	"context"
	"time"

	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/date"
)

// AzureProvider is an interface to access underlying Azure Client objects and supporting services.
// Where practical the original function signature is preserved. Client provides higher
// level operations atop AzureProvider.
type AzureProvider interface {
	MSGraphClient
}

type MSGraphClient interface {
	ListApplications(ctx context.Context, filter string) ([]ApplicationResult, error)
	DeleteApplication(ctx context.Context, applicationObjectID string, permanentlyDelete bool) error
	AddApplicationPassword(ctx context.Context, applicationObjectID string, displayName string, endDateTime time.Time) (PasswordCredentialResult, error)
	RemoveApplicationPassword(ctx context.Context, applicationObjectID string, keyID string) error
}

type ApplicationResult struct {
	autorest.Response `json:"-"`

	AppID               *string               `json:"appId,omitempty"`
	ID                  *string               `json:"id,omitempty"`
	PasswordCredentials []*PasswordCredential `json:"passwordCredentials,omitempty"`
}

type PasswordCredential struct {
	DisplayName *string    `json:"displayName"`
	StartDate   *date.Time `json:"startDateTime,omitempty"`
	EndDate     *date.Time `json:"endDateTime,omitempty"`
	KeyID       *string    `json:"keyId,omitempty"`
	SecretText  *string    `json:"secretText,omitempty"`
}

type PasswordCredentialResult struct {
	autorest.Response `json:"-"`

	PasswordCredential
}
