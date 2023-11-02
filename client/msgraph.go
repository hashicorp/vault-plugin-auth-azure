// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/google/uuid"
	abs "github.com/microsoft/kiota-abstractions-go"
	auth "github.com/microsoftgraph/msgraph-sdk-go-core/authentication"
)

type MSGraphApplication interface {
	GetId() *string
	GetPasswordCredentials() []Credentials // []Credentials
}

type Credentials interface {
	GetKeyId() *uuid.UUID
	GetSecretText() *string
	GetEndDateTime() *time.Time
}

type APIApplicationValues struct {
	Value []*APIApplication `json:"value"`
}

type APIApplication struct {
	ID                  string           `json:"id"`
	PasswordCredentials []APICredentials `json:"passwordCredentials"`
}

func (a *APIApplication) GetId() *string {
	return &a.ID
}

func (a *APIApplication) GetPasswordCredentials() []Credentials {
	x := a.PasswordCredentials
	y := []Credentials{}
	for _, z := range x {
		y = append(y, &z)
	}
	return y
}

type APICredentials struct {
	KeyID       *uuid.UUID `json:"keyId"`
	SecretText  *string    `json:"secretText"`
	EndDateTime *time.Time `json:"endDateTime"`
}

func (a *APICredentials) GetKeyId() *uuid.UUID {
	return a.KeyID
}

func (a *APICredentials) GetSecretText() *string {
	return a.SecretText
}

func (a *APICredentials) GetEndDateTime() *time.Time {
	return a.EndDateTime
}

type MSGraphClient interface {
	GetApplication(ctx context.Context, clientID string) (MSGraphApplication, error)
	AddApplicationPassword(ctx context.Context, applicationObjectID string, displayName string, endDateTime time.Time) (Credentials, error)
	RemoveApplicationPassword(ctx context.Context, applicationObjectID string, keyID *uuid.UUID) error
}

var _ MSGraphClient = (*AppClient)(nil)

type AppClient struct {
	baseUrl      string
	authProvider *auth.AzureIdentityAuthenticationProvider
}

// NewMSGraphApplicationClient returns a new AppClient configured to interact with
// the Microsoft Graph API. It can be configured to target alternative national cloud
// deployments via graphURI. For details on the client configuration see
// https://learn.microsoft.com/en-us/graph/sdks/national-clouds
func NewMSGraphApplicationClient(graphURI string, creds azcore.TokenCredential) (*AppClient, error) {
	scopes := []string{
		fmt.Sprintf("%s/.default", graphURI),
	}

	authProvider, err := auth.NewAzureIdentityAuthenticationProviderWithScopes(creds, scopes)
	if err != nil {
		return nil, err
	}
	ac := &AppClient{
		baseUrl:      fmt.Sprintf("%s/v1.0", graphURI),
		authProvider: authProvider,
	}

	return ac, nil
}

func (c *AppClient) GetApplication(ctx context.Context, clientID string) (MSGraphApplication, error) {
	filter := fmt.Sprintf("appId eq '%s'", clientID)
	query := "$filter=" + url.QueryEscape(filter)
	u, err := url.Parse(fmt.Sprintf("%s/applications?%s", c.baseUrl, query))
	if err != nil {
		return nil, err
	}
	req := abs.NewRequestInformation()
	req.SetUri(*u)
	err = c.authProvider.AuthenticateRequest(ctx, req, nil)
	if err != nil {
		return nil, err
	}
	headers := map[string][]string{
		"accept":        {"application/json"},
		"authorization": req.Headers.Get("Authorization"),
	}
	request := &http.Request{
		Method: "GET",
		URL:    u,
		Header: headers,
	}

	resp, err := http.DefaultClient.Do(request)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("error from msgraph: %v", resp.StatusCode)
	}
	all, err := io.ReadAll(resp.Body)
	apps := APIApplicationValues{}
	err = json.Unmarshal(all, &apps)
	if err != nil {
		return nil, err
	}
	if len(apps.Value) == 0 {
		return nil, fmt.Errorf("no application found")
	}
	if len(apps.Value) > 1 {
		return nil, fmt.Errorf("multiple applications found - double check your client_id")
	}
	return apps.Value[0], nil
}

func (c *AppClient) AddApplicationPassword(ctx context.Context, applicationObjectID string, displayName string, endDateTime time.Time) (Credentials, error) {
	bodyBytes, err := json.Marshal(map[string]interface{}{
		"passwordCredential": map[string]interface{}{
			"displayName": displayName,
			"endDateTime": endDateTime,
		},
	})
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(fmt.Sprintf("%s/applications/%s/addPassword", c.baseUrl, applicationObjectID))
	if err != nil {
		return nil, err
	}
	req := abs.NewRequestInformation()
	req.SetUri(*u)
	err = c.authProvider.AuthenticateRequest(ctx, req, nil)
	if err != nil {
		return nil, err
	}
	headers := map[string][]string{
		"content-type":  {"application/json"},
		"authorization": req.Headers.Get("Authorization"),
	}
	request := &http.Request{
		Method: "POST",
		URL:    u,
		Header: headers,
		Body:   io.NopCloser(bytes.NewBuffer(bodyBytes)),
	}

	resp, err := http.DefaultClient.Do(request)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("error from msgraph: %v", resp.StatusCode)
	}
	all, err := io.ReadAll(resp.Body)
	m := APICredentials{}
	err = json.Unmarshal(all, &m)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (c *AppClient) RemoveApplicationPassword(ctx context.Context, applicationObjectID string, keyID *uuid.UUID) error {
	bodyBytes, err := json.Marshal(map[string]interface{}{"keyId": keyID.String()})
	if err != nil {
		return err
	}
	u, err := url.Parse(fmt.Sprintf("%s/applications/%s/removePassword", c.baseUrl, applicationObjectID))
	if err != nil {
		return err
	}
	req := abs.NewRequestInformation()
	req.SetUri(*u)
	err = c.authProvider.AuthenticateRequest(ctx, req, nil)
	if err != nil {
		return err
	}
	headers := map[string][]string{
		"content-type":  {"application/json"},
		"authorization": req.Headers.Get("Authorization"),
	}
	request := &http.Request{
		Method: "POST",
		URL:    u,
		Header: headers,
		Body:   io.NopCloser(bytes.NewBuffer(bodyBytes)),
	}

	resp, err := http.DefaultClient.Do(request)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("error from msgraph: %v", resp.StatusCode)
	}
	return nil
}
