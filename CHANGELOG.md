## Unreleased

## v0.17.5
### Jun 13, 2025

BUG FIXES:
* fix a bug where logins would fail when resource_group_name contains incorrect character cases (https://github.com/hashicorp/vault-plugin-auth-azure/pull/222)

## v0.17.4

BUG FIXES:
* Fix validation of token claims for Uniform VMSS (https://github.com/hashicorp/vault-plugin-auth-azure/pull/203).

IMPROVEMENTS:
* Updated dependencies:
   * `github.com/Azure/azure-sdk-for-go/sdk/azcore` v1.17.0 -> v1.18.0
   * `github.com/Azure/azure-sdk-for-go/sdk/azidentity` v1.8.2 -> v1.9.0
   * `github.com/coreos/go-oidc/v3` v3.11.0 -> v3.14.1
   * `github.com/microsoftgraph/msgraph-sdk-go` v1.32.0 -> v1.69.0
   * `github.com/microsoftgraph/msgraph-sdk-go-core` v1.0.1 -> v1.3.2
   * `golang.org/x/oauth2` v0.28.0 -> v0.29.0

## v0.17.3

IMPROVEMENTS:
* Require `resource_group_name`, `vm_name`, and `vmss_name` to match token claims on login (https://github.com/hashicorp/vault-plugin-auth-azure/pull/186)
* Updated dependencies:
  * `github.com/Azure/azure-sdk-for-go/sdk/azcore` v1.11.1 -> v1.17.0
  * `github.com/Azure/azure-sdk-for-go/sdk/azidentity` v1.6.0 -> v1.8.2
  * `github.com/hashicorp/vault/api` v1.11.0 -> v1.16.0
  * `github.com/hashicorp/vault/sdk` v0.10.2 -> 1.15.2
  * `golang.org/x/oauth2` v0.21.0 -> v0.28.0

## v0.17.2

IMPROVEMENTS:
* Updated dependencies:
  * `github.com/go-jose/go-jose/v3` v3.0.1 -> v3.0.3
  * `github.com/coreos/go-oidc` v2.2.1 -> 3.11.0
  * `github.com/docker/docker` v25.0.2 -> v25.0.6
  * `github.com/Azure/azure-sdk-for-go/sdk/azidentity` v1.5.1 -> v1.6.0
  * `github.com/hashicorp/go-retryable` v0.7.1 -> v0.7.7
  * `google.golang.org/protobuf` v1.32.0 -> v1.33.0

## v0.17.1

BUGS:

* fix an endless loop of warning spamming the logs on login error

## v0.17.0
IMPROVEMENTS:
* Make `framework.WALPrefix`` a local path [[GH-137](https://github.com/hashicorp/vault-plugin-auth-azure/pull/137)]
* Updated dependencies:
   * `github.com/Azure/azure-sdk-for-go/sdk/azcore` v1.7.1 -> v1.9.1
   * `github.com/Azure/azure-sdk-for-go/sdk/azidentity` v1.3.1 -> v1.5.1
   * `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi` v1.1.0 -> v1.2.0
   * `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources` v1.1.1 -> v1.2.0
   * `github.com/google/uuid` v1.3.1 -> v1.6.0
   * `github.com/hashicorp/go-hclog` v1.5.0 -> v1.6.2
   * `github.com/hashicorp/vault/api` v1.9.2 -> v1.11.0
   * `github.com/hashicorp/vault/sdk` v0.9.2 -> v0.10.2
   * `github.com/microsoftgraph/msgraph-sdk-go` v1.13.0 -> v1.32.0
   * `github.com/microsoftgraph/msgraph-sdk-go-core` v1.0.0 -> v1.0.1
   * `golang.org/x/oauth2` v0.11.0 -> v0.16.0

## v0.16.2
IMPROVEMENTS:
    * Prevent write-ahead-log data from being replicated to performance secondaries [GH-137](https://github.com/hashicorp/vault-plugin-auth-azure/pull/137)
    * Added Azure API configurable retry options [GH-133](https://github.com/hashicorp/vault-plugin-auth-azure/pull/133)

## v0.16.1
IMPROVEMENTS:
* Updated dependencies:
  * github.com/Azure/azure-sdk-for-go/sdk/azcore v1.7.1
  * github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.3.1
  * golang.org/x/oauth2 v0.11.0

## v0.16.0

FEATURES:
* Allow Workload Identity Federation based Azure resources to authenticate with Vault via appID

IMPROVEMENTS:
* Replaces the deprecated [go-autorest](https://github.com/Azure/go-autorest) client with [msgraph-sdk-go](https://github.com/microsoftgraph/msgraph-sdk-go) [[GH-121]](https://github.com/hashicorp/vault-plugin-auth-azure/pull/121)
* Updated dependencies:
  * `github.com/hashicorp/vault/sdk` v0.9.1 -> v0.9.2
  * `github.com/microsoftgraph/msgraph-sdk-go` v1.12.0 -> v1.13.0
  * `golang.org/x/oauth2` v0.9.0 -> v0.10.0

## v0.15.1

BUG FIXES:

* Fix intermittent 401s by preventing performance secondary clusters from rotating root credentials [[GH-118]](https://github.com/hashicorp/vault-plugin-auth-azure/pull/118)

## v0.15.0

IMPROVEMENTS:
* Add display attributes for OpenAPI OperationID's [[GH-106](https://github.com/hashicorp/vault-plugin-auth-azure/pull/106)]
* Updated dependencies:
   * `github.com/Azure/azure-sdk-for-go/sdk/azcore` v1.4.0 -> v1.6.0
   * `github.com/Azure/azure-sdk-for-go/sdk/azidentity` v1.2.2 -> v1.3.0
   * `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4` v4.1.0 -> v4.2.1
   * `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi` v1.0.0 -> v1.1.0
   * `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources` v1.0.0 -> v1.1.1
   * `github.com/Azure/go-autorest/autorest` v0.11.28 -> v0.11.29
   * `github.com/hashicorp/vault/api` v1.9.0 -> v1.9.1
   * `github.com/hashicorp/vault/sdk` v0.8.1 -> v0.9.0
   * `golang.org/x/oauth2` v0.6.0 -> v0.8.0
   * `mvdan.cc/gofumpt` v0.3.1 -> v0.5.0
 * Downgraded dependencies:
   * `github.com/Azure/azure-sdk-for-go` v68.0.0+incompatible -> v67.2.0+incompatible

## v0.14.0

IMPROVEMENTS:

* Enable multiplexing [[GH-96](https://github.com/hashicorp/vault-plugin-auth-azure/pull/96)]
* Upgrade to Go 1.20.2
* Updated dependencies:
   * `github.com/Azure/azure-sdk-for-go` v67.2.0+incompatible -> v68.0.0+incompatible
   * `github.com/Azure/azure-sdk-for-go/sdk/azcore` v1.3.1 -> v1.4.0
   * `github.com/Azure/azure-sdk-for-go/sdk/azidentity` v1.2.1 -> v1.2.2
   * `github.com/hashicorp/go-hclog` v1.4.0 -> v1.5.0
   * `github.com/hashicorp/go-uuid` v1.0.2 -> v1.0.3
   * `golang.org/x/oauth2` v0.4.0 -> v0.6.0

## v0.13.1

BUG FIXES:

* Fix intermittent 401s by preventing performance secondary clusters from rotating root credentials [[GH-118]](https://github.com/hashicorp/vault-plugin-auth-azure/pull/118)

## v0.13.0

FEATURES:

* Add rotate root support to Azure Auth [GH-88](https://github.com/hashicorp/vault-plugin-auth-azure/pull/88)
* Allow any Azure resource that supports managed identities to authenticate with Vault [GH-71](https://github.com/hashicorp/vault-plugin-auth-azure/pull/71)
* Adds support for Virtual Machine Scale Set Flex Authentication [GH-63](https://github.com/hashicorp/vault-plugin-auth-azure/pull/63)

IMPROVEMENTS:
* Updates dependencies
  * `github.com/Azure/azure-sdk-for-go v67.2.0+incompatible`[[GH-88](https://github.com/hashicorp/vault-plugin-auth-azure/pull/88)]
  * `github.com/Azure/go-autorest/autorest v0.11.28` [[GH-65](https://github.com/hashicorp/vault-plugin-auth-azure/pull/65)]
  * `github.com/hashicorp/vault/api v1.8.3` [[GH-82](https://github.com/hashicorp/vault-plugin-auth-azure/pull/82)]
  * `github.com/hashicorp/vault/sdk v0.7.0` [[GH-82](https://github.com/hashicorp/vault-plugin-auth-azure/pull/82)]
  * `github.com/hashicorp/go-hclog v1.4.0`[[GH-78](https://github.com/hashicorp/vault-plugin-auth-azure/pull/78)]
  * `golang.org/x/oauth2 v0.4.0`[[GH-84](https://github.com/hashicorp/vault-plugin-auth-azure/pull/84)]

* Upgrades to Go 1.19 [[GH-65](https://github.com/hashicorp/vault-plugin-auth-azure/pull/65)]
