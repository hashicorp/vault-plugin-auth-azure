// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package azureauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/cidrutil"
	"github.com/hashicorp/vault/sdk/logical"
)

// defaultResourceClientAPIVersion is the API version to use for the operation.
// This is not well documented but supported API version can be queried from
// the GET Providers endpoint.
// https://learn.microsoft.com/en-us/rest/api/resources/providers/get?tabs=HTTP
var defaultResourceClientAPIVersion = "2022-03-01"

const (
	// Depending on the identities are attached to a standalone or VMSS-stemmed virtual machine,
	// we might get different claim patterns in xms_mirid.
	// If system assigned managed identity is enabled and no identity is specified in the Instance
	// Metadata Service request, xms_mirid will be in the format of fmtRID, and xms_az_rid doesn't exist.
	// If system assigned managed identity is not enabled, and only one user-assigned identity exists,
	// xms_mirid will be in the format of fmtRIDWithUserAssignedIdentities, xms_az_rid will be
	// in the format of fmtRID.
	// If system assigned managed identity is not enabled, and multiple user-assigned identities exist,
	// users are required to specify a managed identity in the Instance Metadata Service request.
	// xms_mirid will be in the format of fmtRIDWithUserAssignedIdentities, xms_az_rid will be
	// in the format of fmtRID.
	//
	// See the following for more details
	// https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/managed-identities-faq#what-identity-will-imds-default-to-if-i-dont-specify-the-identity-in-the-request
	// https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity?tabs=portal%2Chttp#rest-endpoint-reference

	// fmtRID is the format of the resource ID that has a virtual machine name
	fmtRID = "/subscriptions/%s/resourcegroups/%s/providers/Microsoft.Compute/virtualMachines/%s"

	// fmtVMSSRID is the format of the resource ID when VMSS is in uniform mode that just has the scaleset name
	fmtVMSSRID = "/subscriptions/%s/resourcegroups/%s/providers/Microsoft.Compute/virtualMachineScaleSets/%s"

	// fmtRIDWithUserAssignedIdentities is the format of the resource ID that has a user-assigned managed identity
	fmtRIDWithUserAssignedIdentities = "/subscriptions/%s/resourcegroups/%s/providers/Microsoft.ManagedIdentity/userAssignedIdentities/%s"

	// fmtResourceGroupID is the format of the resource_id login field
	// /subscriptions/{guid}/resourceGroups/{resource-group-name}/{resource-provider-namespace}/{resource-type}/{resource-name}
	fmtResourceGroupID = "/subscriptions/%s/resourceGroups/%s/%s/%s/%s"

	// fmtVMClaimPattern is used to match the VM name in the xms_az_rid and xms_mirid claims
	// e.g. If VM name is "test-vm", the claim has a substring like "virtualMachines/test-vm"
	fmtVMClaimPattern = "/virtualMachines/%s"

	// fmtVMSSFlexibleClaimPattern is used to match the VMSS name in the xms_az_rid and xms_mirid claims
	// e.g. If VMSS name is "test-vmss", the claim has a substring like "virtualMachines/test-vmss_f9ae3d85"
	fmtVMSSFlexibleClaimPattern = "/virtualMachines/%s_"

	// fmtVMSSUniformClaimPattern is used to match the VMSS name in the xms_az_rid and xms_mirid claims
	// e.g. If VMSS name is "test-vmss", the claim has a substring like "virtualMachineScaleSets/test-vmss"
	fmtVMSSUniformClaimPattern = "/virtualMachineScaleSets/%s"

	// fmtRGClaimPattern is used to match the resource group name in the xms_az_rid and xms_mirid claims
	// e.g If the resource group name is demo, the claim has a substring like "resourcegroups/demo"
	fmtRGClaimPattern = "/resourcegroups/%s"

	// fmtRGClaimCamelCasePattern is similar to fmtRGClaimPattern but with camel case "resourceGroups"
	fmtRGClaimCamelCasePattern = "/resourceGroups/%s"
)

func pathLogin(b *azureAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: "login$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixAzure,
			OperationVerb:   "login",
		},

		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeString,
				Description: `The token role.`,
			},
			"jwt": {
				Type:        framework.TypeString,
				Description: `A signed JWT`,
			},
			"subscription_id": {
				Type:        framework.TypeString,
				Description: `The subscription id for the instance.`,
			},
			"resource_group_name": {
				Type:        framework.TypeString,
				Description: `The resource group from the instance.`,
			},
			"vm_name": {
				Type:        framework.TypeString,
				Description: `The name of the virtual machine. This value is ignored if vmss_name is specified.`,
			},
			"vmss_name": {
				Type:        framework.TypeString,
				Description: `The name of the virtual machine scale set the instance is in.`,
			},
			"resource_id": {
				Type: framework.TypeString,
				Description: `The fully qualified ID of the resource, including` +
					`the resource name and resource type. Use the format, ` +
					`/subscriptions/{guid}/resourceGroups/{resource-group-name}/{resource-provider-namespace}/{resource-type}/{resource-name}. ` +
					`This value is ignored if vm_name or vmss_name is specified.`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathLogin,
			},
			logical.AliasLookaheadOperation: &framework.PathOperation{
				Callback: b.pathLogin,
			},
			logical.ResolveRoleOperation: &framework.PathOperation{
				Callback: b.pathResolveRole,
			},
		},

		HelpSynopsis:    pathLoginHelpSyn,
		HelpDescription: pathLoginHelpDesc,
	}
}

func (b *azureAuthBackend) pathResolveRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role").(string)
	if roleName == "" {
		return logical.ErrorResponse("role is required"), nil
	}

	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("invalid role name %q", roleName)), nil
	}

	return logical.ResolveRoleResponse(roleName)
}

func (b *azureAuthBackend) pathLogin(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	signedJwt := data.Get("jwt").(string)
	if signedJwt == "" {
		return logical.ErrorResponse("jwt is required"), nil
	}
	roleName := data.Get("role").(string)
	if roleName == "" {
		return logical.ErrorResponse("role is required"), nil
	}

	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("invalid role name %q", roleName)), nil
	}

	if len(role.TokenBoundCIDRs) > 0 {
		if req.Connection == nil {
			b.Logger().Warn("token bound CIDRs found but no connection information available for validation")
			return nil, logical.ErrPermissionDenied
		}
		if !cidrutil.RemoteAddrIsOk(req.Connection.RemoteAddr, role.TokenBoundCIDRs) {
			return nil, logical.ErrPermissionDenied
		}
	}

	subscriptionID := data.Get("subscription_id").(string)
	resourceGroupName := data.Get("resource_group_name").(string)
	vmssName := data.Get("vmss_name").(string)
	vmName := data.Get("vm_name").(string)
	resourceID := data.Get("resource_id").(string)

	if subscriptionID != "" && !validateAzureField(guidRx, subscriptionID) {
		return logical.ErrorResponse(fmt.Sprintf("invalid subscription id %q", subscriptionID)), nil
	}
	if resourceGroupName != "" && !validateAzureField(rgRx, resourceGroupName) {
		return logical.ErrorResponse(fmt.Sprintf("invalid resource group name %q", resourceGroupName)), nil
	}
	if vmssName != "" && !validateAzureField(nameRx, vmssName) {
		return logical.ErrorResponse(fmt.Sprintf("invalid vmss_name %q", vmssName)), nil
	}
	if vmName != "" && !validateAzureField(nameRx, vmName) {
		return logical.ErrorResponse(fmt.Sprintf("invalid vm name %q", vmName)), nil
	}

	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve backend configuration: %w", err)
	}
	if config == nil {
		config = new(azureConfig)
	}

	provider, err := b.getProvider(ctx, config)
	if err != nil {
		return nil, err
	}

	// The OIDC verifier verifies the signature and checks the 'aud' and 'iss'
	// claims and expiration time
	idToken, err := provider.TokenVerifier().Verify(ctx, signedJwt)
	if err != nil {
		return nil, err
	}

	claims := new(additionalClaims)
	if err := idToken.Claims(claims); err != nil {
		return nil, err
	}

	// Check additional claims in token
	if err := claims.verifyRole(role); err != nil {
		return nil, err
	}

	if err := b.verifyResource(ctx, subscriptionID, resourceGroupName, vmName, vmssName, resourceID, claims, role); err != nil {
		return nil, err
	}

	auth := &logical.Auth{
		DisplayName: claims.ObjectID,
		Alias: &logical.Alias{
			Name: claims.ObjectID,
			Metadata: map[string]string{
				"resource_group_name": resourceGroupName,
				"subscription_id":     subscriptionID,
			},
		},
		InternalData: map[string]interface{}{
			"role": roleName,
		},
		Metadata: map[string]string{
			"role":                roleName,
			"resource_group_name": resourceGroupName,
			"subscription_id":     subscriptionID,
		},
	}

	if vmName != "" {
		auth.Alias.Metadata["vm_name"] = vmName
		auth.Metadata["vm_name"] = vmName
	}
	if vmssName != "" {
		auth.Alias.Metadata["vmss_name"] = vmssName
		auth.Metadata["vmss_name"] = vmssName
	}
	if resourceID != "" {
		auth.Alias.Metadata["resource_id"] = resourceID
		auth.Metadata["resource_id"] = resourceID
	}
	if claims.AppID != "" {
		auth.Alias.Metadata["app_id"] = claims.AppID
		auth.Metadata["app_id"] = claims.AppID
	}

	role.PopulateTokenAuth(auth)

	resp := &logical.Response{
		Auth: auth,
	}

	// Add groups to group aliases
	for _, groupID := range claims.GroupIDs {
		if groupID == "" {
			continue
		}
		resp.Auth.GroupAliases = append(resp.Auth.GroupAliases, &logical.Alias{
			Name: groupID,
		})
	}

	return resp, nil
}

func (b *azureAuthBackend) verifyResource(ctx context.Context, subscriptionID, resourceGroupName, vmName, vmssName, resourceID string, claims *additionalClaims, role *azureRole) error {
	// If not checking anything with the resource id, exit early
	if len(role.BoundResourceGroups) == 0 && len(role.BoundSubscriptionsIDs) == 0 && len(role.BoundLocations) == 0 && len(role.BoundScaleSets) == 0 {
		return nil
	}

	if subscriptionID == "" || resourceGroupName == "" {
		return errors.New("subscription_id and resource_group_name are required")
	}

	var location *string
	principalIDs := map[string]struct{}{}
	switch {
	// If vmss name is specified, the vm name will be ignored and only the scale set
	// will be verified since vm names are generated automatically for scale sets
	case vmssName != "":
		// Check VMSS name matches in any of the token's xms_az_rid or xm_mirid claims
		if err := claims.verifyVMSS(vmssName); err != nil {
			return err
		}

		client, err := b.provider.VMSSClient(subscriptionID)
		if err != nil {
			return err
		}

		// Omit armcompute.ExpandTypesForGetVMScaleSetsUserData since we do not need that information for purpose of authenticating an instance
		vmss, err := client.Get(ctx, resourceGroupName, vmssName, nil)
		if err != nil {
			return fmt.Errorf("unable to retrieve virtual machine scale set metadata: %w", err)
		}

		// Check bound scale sets
		if len(role.BoundScaleSets) > 0 && !strListContains(role.BoundScaleSets, vmssName) {
			return errors.New("scale set not authorized")
		}

		location = vmss.Location

		if vmss.Identity == nil {
			return errors.New("vmss client did not return identity information")
		}
		// if system-assigned identity's principal id is available
		if vmss.Identity.PrincipalID != nil {
			principalIDs[convertPtrToString(vmss.Identity.PrincipalID)] = struct{}{}
		}
		// if not, look for user-assigned identities
		for userIdentityID, userIdentity := range vmss.Identity.UserAssignedIdentities {
			// Principal ID is not nil for VMSS uniform orchestration mode
			if userIdentity.PrincipalID != nil {
				principalIDs[convertPtrToString(userIdentity.PrincipalID)] = struct{}{}
				continue
			}

			msiID, err := arm.ParseResourceID(userIdentityID)
			if err != nil {
				return fmt.Errorf("unable to parse the user-assigned identity resource ID %q: %w", userIdentityID, err)
			}

			// Principal ID is nil for VMSS flex orchestration mode, so we
			// must look up the user-assigned identity using the MSI client
			msiClient, err := b.provider.MSIClient(msiID.SubscriptionID)
			if err != nil {
				return fmt.Errorf("failed to create client to retrieve user-assigned identity: %w", err)
			}
			userIdentityResponse, err := msiClient.Get(ctx, msiID.ResourceGroupName, msiID.Name, nil)
			if err != nil {
				return fmt.Errorf("unable to retrieve user assigned identity metadata: %w", err)
			}

			if userIdentityResponse.Properties != nil && userIdentityResponse.Properties.PrincipalID != nil {
				principalIDs[*userIdentityResponse.Properties.PrincipalID] = struct{}{}
			}
		}
	case vmName != "":
		// Check VM name matches in any of the token's xms_az_rid or xm_mirid claims
		if err := claims.verifyVM(vmName); err != nil {
			return err
		}

		client, err := b.provider.ComputeClient(subscriptionID)
		if err != nil {
			return err
		}

		instanceView := armcompute.InstanceViewTypesInstanceView
		options := armcompute.VirtualMachinesClientGetOptions{
			Expand: &instanceView,
		}

		vm, err := client.Get(ctx, resourceGroupName, vmName, &options)
		if err != nil {
			return fmt.Errorf("unable to retrieve virtual machine metadata: %w", err)
		}

		location = vm.Location

		if vm.Identity == nil {
			return errors.New("vm client did not return identity information")
		}
		// Check bound scale sets
		if len(role.BoundScaleSets) > 0 {
			return errors.New("bound scale set defined but this vm isn't in a scale set")
		}
		// if system-assigned identity's principal id is available
		if vm.Identity.PrincipalID != nil {
			principalIDs[convertPtrToString(vm.Identity.PrincipalID)] = struct{}{}
		}
		// if not, look for user-assigned identities
		for _, userIdentity := range vm.Identity.UserAssignedIdentities {
			principalIDs[convertPtrToString(userIdentity.PrincipalID)] = struct{}{}
		}
	case resourceID != "":
		// this is the generic case that should enable Azure services that
		// support managed identities to authenticate to Vault
		if len(role.BoundScaleSets) > 0 {
			return errors.New("scale set requires the vmss_name field to be set")
		}

		apiVersion, err := b.getAPIVersionForResource(ctx, subscriptionID, resourceID)
		if err != nil {
			return err
		}

		client, err := b.provider.ResourceClient(subscriptionID)
		if err != nil {
			return err
		}

		resp, err := client.GetByID(ctx, resourceID, apiVersion, nil)
		if err != nil {
			return fmt.Errorf("unable to retrieve user assigned identity metadata: %w", err)
		}
		if resp.Identity == nil {
			return errors.New("client did not return identity information")
		}
		// if system-assigned identity's principal id is available
		if resp.Identity.PrincipalID != nil {
			principalIDs[convertPtrToString(resp.Identity.PrincipalID)] = struct{}{}
		}
		// if not, look for user-assigned identities
		for _, userIdentity := range resp.Identity.UserAssignedIdentities {
			principalIDs[convertPtrToString(userIdentity.PrincipalID)] = struct{}{}
		}
	default:
		// in some cases (particularly WIF), a vm/vmss/resource_id might not be provided, in that case
		// we'll try to authenticate by matching the claim's app_id to the list of managed identities
		// (see the comment below on that)
		if claims.AppID == "" {
			return errors.New("one of vm_name, vmss_name, resource_id, or an appid JWT claim must be provided")
		}
	}

	if err := claims.verifyResourceGroup(resourceGroupName, vmName, vmssName, resourceID); err != nil {
		return err
	}

	var wifMatch bool
	// Ensure the token OID is the principal id of the system-assigned identity
	// or one of the user-assigned identities
	if _, ok := principalIDs[claims.ObjectID]; !ok {
		// if it isn't, check the appID and see if _that_ exists. In some cases, particularly WIF (workload identity
		// federation), there is no principal that matches the incoming ObjectID. In this case, we can still validate
		// by checking the appID against the list of managed identities. (The appID is valid for use with authorizing
		// claims, per https://learn.microsoft.com/en-us/azure/active-directory/develop/access-tokens#payload-claims)
		if claims.AppID == "" {
			return errors.New("token object id does not match expected identities, and no app id was found")
		}

		clientIDs := map[string]struct{}{}
		c, err := b.provider.MSIClient(subscriptionID)
		if err != nil {
			return fmt.Errorf("failed to create client to retrieve app ids: %w", err)
		}

		// aggregate the list of valid resource groups to check (the resource group provided by the resource, plus
		// the resources specified as valid by the role entry)
		rgChecks := []string{resourceGroupName}
		rgChecks = append(rgChecks, role.BoundResourceGroups...)

		for _, rg := range rgChecks {
			pager := c.NewListByResourceGroupPager(rg, &armmsi.UserAssignedIdentitiesClientListByResourceGroupOptions{})
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					// don't fail the whole auth, but note that a page failed to load:
					b.Logger().Warn("couldn't load next page for", "resource_group", rg, "error", err.Error())

					// ensure we don't loop forever
					break
				}
				for _, id := range page.Value {
					if id.Properties != nil && id.Properties.ClientID != nil {
						clientIDs[*id.Properties.ClientID] = struct{}{}
					}
				}
			}
		}

		if _, ok := clientIDs[claims.AppID]; !ok {
			return errors.New("neither token object id nor token app id match expected identities")
		}
		wifMatch = true
	}

	// Check bound subscriptions
	if len(role.BoundSubscriptionsIDs) > 0 && !strListContains(role.BoundSubscriptionsIDs, subscriptionID) {
		return errors.New("subscription not authorized")
	}

	// Check bound resource groups unless we matched due to WIF (if we matched a valid clientID/appID by resource group, the
	// group validity is implict)
	if !wifMatch && len(role.BoundResourceGroups) > 0 && !strListContains(role.BoundResourceGroups, resourceGroupName) {
		return errors.New("resource group not authorized")
	}

	// Check bound locations
	if len(role.BoundLocations) > 0 {
		if location == nil {
			return errors.New("location is empty")
		}
		if !strListContains(role.BoundLocations, convertPtrToString(location)) {
			return errors.New("location not authorized")
		}
	}

	return nil
}

func (b *azureAuthBackend) pathLoginRenew(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := req.Auth.InternalData["role"].(string)
	if roleName == "" {
		return nil, errors.New("failed to fetch role_name during renewal")
	}

	// Ensure that the Role still exists.
	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("failed to validate role %s during renewal: %w", roleName, err)
	}
	if role == nil {
		return nil, fmt.Errorf("role %s does not exist during renewal", roleName)
	}

	resp := &logical.Response{Auth: req.Auth}
	resp.Auth.TTL = role.TokenTTL
	resp.Auth.MaxTTL = role.TokenMaxTTL
	resp.Auth.Period = role.TokenPeriod
	return resp, nil
}

type additionalClaims struct {
	NotBefore jsonTime `json:"nbf"`
	ObjectID  string   `json:"oid"`
	AppID     string   `json:"appid"`
	GroupIDs  []string `json:"groups"`
	// XMSAzureResourceID is used to identify the
	// resource ID of the resource to which the identity is assigned for
	// managed identity authentication
	XMSAzureResourceID string `json:"xms_az_rid,omitempty"`
	// XMSManagedIdentityResourceID is typically included in tokens
	// that are issued to a managed identity in Azure, particularly when the token is
	// obtained from the Azure Instance Metadata Service (IMDS) on an Azure VM.
	// This claim indicates the Azure resource ID of the managed identity's resource,
	// such as a virtual machine.
	XMSManagedIdentityResourceID string `json:"xms_mirid,omitempty"`
}

// verifyRole checks the additional claims in the token against the role
func (c *additionalClaims) verifyRole(role *azureRole) error {
	notBefore := time.Time(c.NotBefore)
	if notBefore.After(time.Now()) {
		return fmt.Errorf("token is not yet valid (Token Not Before: %v)", notBefore)
	}

	isBoundSPWildcard := len(role.BoundServicePrincipalIDs) == 1 && role.BoundServicePrincipalIDs[0] == "*"
	isBoundGroupWildcard := len(role.BoundGroupIDs) == 1 && role.BoundGroupIDs[0] == "*"
	isBoundSPEmpty := len(role.BoundServicePrincipalIDs) == 0
	isBoundGroupEmpty := len(role.BoundGroupIDs) == 0

	// Both BoundServicePrincipalIDs and BoundGroupIDs cannot be "*" or empty at the same time
	if (isBoundSPWildcard && isBoundGroupWildcard) || (isBoundSPEmpty && isBoundGroupEmpty) {
		return fmt.Errorf("expected specific bound_group_ids or bound_service_principal_ids; both cannot be empty or '*'")
	}

	switch {
	case len(role.BoundServicePrincipalIDs) == 1 && role.BoundServicePrincipalIDs[0] == "*":
		// Globbing on PrincipalIDs; can skip Service Principal ID check
	case len(role.BoundServicePrincipalIDs) > 0:
		if !strListContains(role.BoundServicePrincipalIDs, c.ObjectID) {
			return fmt.Errorf("service principal not authorized: %s", c.ObjectID)
		}
	}

	switch {
	case len(role.BoundGroupIDs) == 1 && role.BoundGroupIDs[0] == "*":
		// Globbing on GroupIDs; can skip group ID check
	case len(role.BoundGroupIDs) > 0:
		var found bool
		for _, group := range c.GroupIDs {
			if strListContains(role.BoundGroupIDs, group) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("groups not authorized: %v", c.GroupIDs)
		}
	}

	return nil
}

// verifyXMSClaims checks if the claimPattern when formatted with loginValue is
// present in the xms_az_rid or xms_mirid claims
func (c *additionalClaims) verifyXMSClaims(claimPattern, loginKey, loginValue string) error {
	if c.XMSAzureResourceID == "" && c.XMSManagedIdentityResourceID == "" {
		return errors.New("xms_az_rid and xms_mirid claims are missing from token")
	}
	var errs []error

	if c.XMSAzureResourceID != "" {
		if containsInsensitive(c.XMSAzureResourceID, fmt.Sprintf(claimPattern, loginValue)) {
			return nil
		}
		errs = append(errs, fmt.Errorf("xms_az_rid token claim does not match %s %s", loginKey, loginValue))
	}

	if containsInsensitive(c.XMSManagedIdentityResourceID, fmt.Sprintf(claimPattern, loginValue)) {
		return nil
	}
	errs = append(errs, fmt.Errorf("xms_mirid token claim does not match %s %s", loginKey, loginValue))

	return errors.Join(errs...)
}

// verifyVM checks the additional claims in the token against
// the provided vm_name field on login
func (c *additionalClaims) verifyVM(vmName string) error {
	return c.verifyXMSClaims(fmtVMClaimPattern, "vm_name", vmName)
}

// verifyVMSS checks the additional claims in the token against
// the provided vm_name field on login. We have to check both the
// uniform and flexible claim patterns. Since flexible is recommended
// and default, check it first; if it fails, fall back to uniform.
func (c *additionalClaims) verifyVMSS(vmssName string) error {
	var errs []error
	if err := c.verifyXMSClaims(fmtVMSSFlexibleClaimPattern, "vmss_name", vmssName); err != nil {
		errs = append(errs, fmt.Errorf("failed to verify flexible vmss claim: %w", err))

		if err := c.verifyXMSClaims(fmtVMSSUniformClaimPattern, "vmss_name", vmssName); err != nil {
			errs = append(errs, fmt.Errorf("failed to verify uniform vmss claim: %w", err))
			return errors.Join(errs...)
		}
	}

	return nil
}

// verifyResourceGroup checks the additional claims in the token against
// the provided resource_group_name field on login
func (c *additionalClaims) verifyResourceGroup(resourceGroupName string, vmName, vmssName, resourceID string) error {
	if vmssName == "" && vmName == "" {
		if containsInsensitive(resourceID, fmt.Sprintf(fmtRGClaimPattern, resourceGroupName)) ||
			containsInsensitive(resourceID, fmt.Sprintf(fmtRGClaimCamelCasePattern, resourceGroupName)) {
			return nil
		}
		return errors.New("provided resource_id does not match resource_group_name")
	}

	return c.verifyXMSClaims(fmtRGClaimPattern, "resource_group_name", resourceGroupName)
}

const (
	pathLoginHelpSyn  = `Authenticates Azure Managed Service Identities with Vault.`
	pathLoginHelpDesc = `
Authenticate Azure Managed Service Identities.
`
)

func convertPtrToString(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}

// getAPIVersionForResource queries the supported API versions for a given
// resource. This will cache results so that subsequent logins will not make
// the same API call more than once.
func (b *azureAuthBackend) getAPIVersionForResource(ctx context.Context, subscriptionID, resourceID string) (string, error) {
	resourceType, err := arm.ParseResourceType(resourceID)
	if err != nil {
		return "", fmt.Errorf("unable to parse the resource ID: %q", resourceID)
	}

	b.cacheLock.RLock()
	// short circuit if we have already cached the api version for this resource type
	if apiVersion, ok := b.resourceAPIVersionCache[resourceType.String()]; ok {
		b.cacheLock.RUnlock()
		return apiVersion, nil
	}
	b.cacheLock.RUnlock()

	client, err := b.provider.ProvidersClient(subscriptionID)
	if err != nil {
		return "", err
	}

	response, err := client.Get(ctx, resourceType.Namespace, nil)
	if err != nil {
		return "", fmt.Errorf("unable to get the provider for resource %q: %w", resourceID, err)
	}

	var resourceTypeResp *armresources.ProviderResourceType
	for _, rt := range response.Provider.ResourceTypes {
		// look through the list of ResourceTypes until we find the one
		// corresponding to the resource that is being used on this login
		if convertPtrToString(rt.ResourceType) == resourceType.Type {
			resourceTypeResp = rt
		}
	}

	apiVersion := defaultResourceClientAPIVersion
	if resourceTypeResp == nil {
		return apiVersion, nil
	}

	// APIVersions are dates in descending order
	for _, v := range resourceTypeResp.APIVersions {
		version := convertPtrToString(v)
		// we will grab the most recent API version unless it is a preview
		// which will have a "-preview" suffix
		if strings.Contains(version, "preview") {
			continue
		}
		apiVersion = version
		break
	}

	b.cacheLock.Lock()
	// this resource type hasn't been seen yet so cache it
	b.resourceAPIVersionCache[resourceType.String()] = apiVersion
	b.cacheLock.Unlock()

	return apiVersion, nil
}

func containsInsensitive(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return strings.Contains(strings.ToLower(a), strings.ToLower(b))
}
