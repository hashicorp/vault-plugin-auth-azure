// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"time"

	"github.com/google/uuid"
	graphmodels "github.com/microsoftgraph/msgraph-sdk-go/models"
)

type MSGraphClient interface {
	ListApplications(ctx context.Context, filter string) ([]graphmodels.Applicationable, error)
	DeleteApplication(ctx context.Context, applicationObjectID string) error
	AddApplicationPassword(ctx context.Context, applicationObjectID string, displayName string, endDateTime time.Time) (graphmodels.PasswordCredentialable, error)
	RemoveApplicationPassword(ctx context.Context, applicationObjectID string, keyID *uuid.UUID) error
}
