package api

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/authorization/mgmt/authorization"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/date"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/hashicorp/vault/sdk/logical"
)

var _ MSGraphClient = (*AppClient)(nil)

type AppClient struct {
	Client   authorization.BaseClient
	GraphURI string
}

type listApplicationsResponse struct {
	Value []ApplicationResult `json:"value"`
}

type ClientSettings struct {
	SubscriptionID string
	TenantID       string
	ClientID       string
	ClientSecret   string
	Environment    azure.Environment
	PluginEnv      *logical.PluginEnvironment
}

func GetGraphURI(env string) (string, error) {
	switch env {
	case "AzurePublicCloud", "":
		return "https://graph.microsoft.com", nil
	case "AzureUSGovernmentCloud":
		return "https://graph.microsoft.us", nil
	case "AzureGermanCloud":
		return "https://graph.microsoft.de", nil
	case "AzureChinaCloud":
		return "https://microsoftgraph.chinacloudapi.cn", nil
	default:
		return "", fmt.Errorf("environment '%s' unknown", env)
	}
}

// NewMSGraphApplicationClient creates a new MS Graph Client
// to allow interaction with the MS Graph v1.0 API.
func NewMSGraphApplicationClient(subscriptionId string, userAgentExtension string, graphURI string, auth autorest.Authorizer) (*AppClient, error) {
	client := authorization.NewWithBaseURI(graphURI, subscriptionId)
	client.Authorizer = auth

	if userAgentExtension != "" {
		err := client.AddToUserAgent(userAgentExtension)
		if err != nil {
			return nil, fmt.Errorf("failed to add extension to user agent")
		}
	}

	ac := &AppClient{
		Client:   client,
		GraphURI: graphURI,
	}
	return ac, nil
}

func (c *AppClient) AddToUserAgent(extension string) error {
	return c.Client.AddToUserAgent(extension)
}

// ListApplications lists all Azure application in organization based on a filter.
func (c *AppClient) ListApplications(ctx context.Context, filter string) ([]ApplicationResult, error) {
	filterArgs := url.Values{}
	if filter != "" {
		filterArgs.Set("$filter", filter)
	}
	preparer := c.GetPreparer(
		autorest.AsGet(),
		autorest.WithPath(fmt.Sprintf("/v1.0/applications?%s", filterArgs.Encode())),
	)
	listAppResp := listApplicationsResponse{}
	err := c.SendRequest(ctx, preparer,
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&listAppResp),
	)
	if err != nil {
		return nil, err
	}

	return listAppResp.Value, nil
}

// AddApplicationPassword adds an Azure application password.
func (c *AppClient) AddApplicationPassword(ctx context.Context, applicationObjectID string, displayName string, endDateTime time.Time) (PasswordCredentialResult, error) {
	req, err := c.addPasswordPreparer(ctx, applicationObjectID, displayName, date.Time{endDateTime})
	if err != nil {
		return PasswordCredentialResult{}, autorest.NewErrorWithError(err, "provider", "AddApplicationPassword", nil, "Failure preparing request")
	}

	resp, err := c.addPasswordSender(req)
	if err != nil {
		result := PasswordCredentialResult{
			Response: autorest.Response{Response: resp},
		}
		return result, autorest.NewErrorWithError(err, "provider", "AddApplicationPassword", resp, "Failure sending request")
	}

	result, err := c.addPasswordResponder(resp)
	if err != nil {
		return result, autorest.NewErrorWithError(err, "provider", "AddApplicationPassword", resp, "Failure responding to request")
	}

	return result, nil
}

func (c *AppClient) addPasswordPreparer(ctx context.Context, applicationObjectID string, displayName string, endDateTime date.Time) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"applicationObjectId": autorest.Encode("path", applicationObjectID),
	}

	parameters := struct {
		PasswordCredential *PasswordCredential `json:"passwordCredential"`
	}{
		PasswordCredential: &PasswordCredential{
			DisplayName: to.StringPtr(displayName),
			EndDate:     &endDateTime,
		},
	}

	preparer := autorest.CreatePreparer(
		autorest.AsContentType("application/json; charset=utf-8"),
		autorest.AsPost(),
		autorest.WithBaseURL(c.Client.BaseURI),
		autorest.WithPathParameters("/v1.0/applications/{applicationObjectId}/addPassword", pathParameters),
		autorest.WithJSON(parameters),
		c.Client.WithAuthorization())
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

func (c *AppClient) addPasswordSender(req *http.Request) (*http.Response, error) {
	sd := autorest.GetSendDecorators(req.Context(), autorest.DoRetryForStatusCodes(c.Client.RetryAttempts, c.Client.RetryDuration, autorest.StatusCodesForRetry...))
	return autorest.SendWithSender(c.Client, req, sd...)
}

func (c *AppClient) addPasswordResponder(resp *http.Response) (PasswordCredentialResult, error) {
	var result PasswordCredentialResult
	err := autorest.Respond(
		resp,
		c.Client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return result, err
}

// RemoveApplicationPassword removes an Azure application password.
func (c *AppClient) RemoveApplicationPassword(ctx context.Context, applicationObjectID string, keyID string) error {
	req, err := c.removePasswordPreparer(ctx, applicationObjectID, keyID)
	if err != nil {
		return autorest.NewErrorWithError(err, "provider", "RemoveApplicationPassword", nil, "Failure preparing request")
	}

	resp, err := c.removePasswordSender(req)
	if err != nil {
		return autorest.NewErrorWithError(err, "provider", "RemoveApplicationPassword", resp, "Failure sending request")
	}

	_, err = c.removePasswordResponder(resp)
	if err != nil {
		return autorest.NewErrorWithError(err, "provider", "RemoveApplicationPassword", resp, "Failure responding to request")
	}

	return nil
}

func (c *AppClient) removePasswordPreparer(ctx context.Context, applicationObjectID string, keyID string) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"applicationObjectId": autorest.Encode("path", applicationObjectID),
	}

	parameters := struct {
		KeyID string `json:"keyId"`
	}{
		KeyID: keyID,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsContentType("application/json; charset=utf-8"),
		autorest.AsPost(),
		autorest.WithBaseURL(c.Client.BaseURI),
		autorest.WithPathParameters("/v1.0/applications/{applicationObjectId}/removePassword", pathParameters),
		autorest.WithJSON(parameters),
		c.Client.WithAuthorization())
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

func (c *AppClient) removePasswordSender(req *http.Request) (*http.Response, error) {
	sd := autorest.GetSendDecorators(req.Context(), autorest.DoRetryForStatusCodes(c.Client.RetryAttempts, c.Client.RetryDuration, autorest.StatusCodesForRetry...))
	return autorest.SendWithSender(c.Client, req, sd...)
}

func (c *AppClient) removePasswordResponder(resp *http.Response) (autorest.Response, error) {
	var result autorest.Response
	err := autorest.Respond(
		resp,
		c.Client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusNoContent),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = resp
	return result, err
}

// DeleteApplication deletes an Azure application object.
func (c *AppClient) DeleteApplication(ctx context.Context, applicationObjectID string, permanentlyDelete bool) error {
	req, err := c.deleteApplicationPreparer(ctx, applicationObjectID)
	if err != nil {
		return autorest.NewErrorWithError(err, "provider", "DeleteApplication", nil, "Failure preparing request")
	}

	resp, err := c.deleteApplicationSender(req)
	if err != nil {
		return autorest.NewErrorWithError(err, "provider", "DeleteApplication", resp, "Failure sending request")
	}

	err = autorest.Respond(
		resp,
		c.Client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusNoContent, http.StatusNotFound),
		autorest.ByClosing())

	if err != nil {
		return autorest.NewErrorWithError(err, "provider", "DeleteApplication", resp, "Failure responding to request")
	}

	if permanentlyDelete {
		err = c.deleteDeletedItem(ctx, applicationObjectID)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *AppClient) deleteApplicationPreparer(ctx context.Context, applicationObjectID string) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"applicationObjectId": autorest.Encode("path", applicationObjectID),
	}

	preparer := autorest.CreatePreparer(
		autorest.AsContentType("application/json; charset=utf-8"),
		autorest.AsDelete(),
		autorest.WithBaseURL(c.Client.BaseURI),
		autorest.WithPathParameters("/v1.0/applications/{applicationObjectId}", pathParameters),
		c.Client.WithAuthorization())
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

func (c *AppClient) deleteApplicationSender(req *http.Request) (*http.Response, error) {
	sd := autorest.GetSendDecorators(req.Context(), autorest.DoRetryForStatusCodes(c.Client.RetryAttempts, c.Client.RetryDuration, autorest.StatusCodesForRetry...))
	return autorest.SendWithSender(c.Client, req, sd...)
}

func (c *AppClient) deleteDeletedItem(ctx context.Context, id string) error {
	pathParams := map[string]interface{}{
		"id": id,
	}

	preparer := c.GetPreparer(
		autorest.AsDelete(),
		autorest.WithPathParameters("/v1.0/directory/deletedItems/{id}", pathParams),
	)

	return c.SendRequest(ctx, preparer, autorest.WithErrorUnlessStatusCode(http.StatusOK, http.StatusNoContent))
}

func (c *AppClient) GetPreparer(prepareDecorators ...autorest.PrepareDecorator) autorest.Preparer {
	decs := []autorest.PrepareDecorator{
		autorest.AsContentType("application/json; charset=utf-8"),
		autorest.WithBaseURL(c.Client.BaseURI),
		c.Client.WithAuthorization(),
	}
	decs = append(decs, prepareDecorators...)
	preparer := autorest.CreatePreparer(decs...)
	return preparer
}

func (c *AppClient) SendRequest(ctx context.Context, preparer autorest.Preparer, respDecs ...autorest.RespondDecorator) error {
	req, err := preparer.Prepare((&http.Request{}).WithContext(ctx))
	if err != nil {
		return err
	}

	sender := autorest.GetSendDecorators(req.Context(),
		autorest.DoRetryForStatusCodes(c.Client.RetryAttempts, c.Client.RetryDuration, autorest.StatusCodesForRetry...),
	)
	resp, err := autorest.SendWithSender(c.Client, req, sender...)
	if err != nil {
		return err
	}

	// Put ByInspecting() before any provided decorators
	respDecs = append([]autorest.RespondDecorator{c.Client.ByInspecting()}, respDecs...)
	respDecs = append(respDecs, autorest.ByClosing())

	return autorest.Respond(resp, respDecs...)
}
