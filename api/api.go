package api

import (
	"context"
	"time"

	"github.com/google/uuid"
	graphmodels "github.com/microsoftgraph/msgraph-sdk-go/models"
)

// AzureProvider is an interface to access underlying Azure Client objects and supporting services.
// Where practical the original function signature is preserved. Client provides higher
// level operations atop AzureProvider.
type AzureProvider interface {
	MSGraphClient
}

type MSGraphClient interface {
	ListApplications(ctx context.Context, filter string) ([]graphmodels.Applicationable, error)
	DeleteApplication(ctx context.Context, applicationObjectID string) error
	AddApplicationPassword(ctx context.Context, applicationObjectID string, displayName string, endDateTime time.Time) (graphmodels.PasswordCredentialable, error)
	RemoveApplicationPassword(ctx context.Context, applicationObjectID string, keyID *uuid.UUID) error
}
