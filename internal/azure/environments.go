package internal

// This file describes Azure Environment types
// and constants required by our Azure provider
// implementation

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

const (
	// EnvironmentFilepathName captures the name of the environment variable containing the path to the file
	// to be used while populating the Azure Environment.
	EnvironmentFilepathName = "AZURE_ENVIRONMENT_FILEPATH"
)

var environments = map[string]Environment{
	"AZURECLOUD":       PublicCloud,
	"AZUREPUBLICCLOUD": PublicCloud,
}

// ResourceIdentifier contains a set of Azure resource IDs.
type ResourceIdentifier struct {
	Graph               string `json:"graph"`
	KeyVault            string `json:"keyVault"`
	Datalake            string `json:"datalake"`
	Batch               string `json:"batch"`
	OperationalInsights string `json:"operationalInsights"`
	OSSRDBMS            string `json:"ossRDBMS"`
	Storage             string `json:"storage"`
	Synapse             string `json:"synapse"`
	ServiceBus          string `json:"serviceBus"`
	SQLDatabase         string `json:"sqlDatabase"`
	CosmosDB            string `json:"cosmosDB"`
	ManagedHSM          string `json:"managedHSM"`
	MicrosoftGraph      string `json:"microsoftGraph"`
}

// Environment represents a set of endpoints for each of Azure's Clouds.
type Environment struct {
	Name                         string             `json:"name"`
	ManagementPortalURL          string             `json:"managementPortalURL"`
	PublishSettingsURL           string             `json:"publishSettingsURL"`
	ServiceManagementEndpoint    string             `json:"serviceManagementEndpoint"`
	ResourceManagerEndpoint      string             `json:"resourceManagerEndpoint"`
	ActiveDirectoryEndpoint      string             `json:"activeDirectoryEndpoint"`
	GalleryEndpoint              string             `json:"galleryEndpoint"`
	KeyVaultEndpoint             string             `json:"keyVaultEndpoint"`
	ManagedHSMEndpoint           string             `json:"managedHSMEndpoint"`
	GraphEndpoint                string             `json:"graphEndpoint"`
	ServiceBusEndpoint           string             `json:"serviceBusEndpoint"`
	BatchManagementEndpoint      string             `json:"batchManagementEndpoint"`
	MicrosoftGraphEndpoint       string             `json:"microsoftGraphEndpoint"`
	StorageEndpointSuffix        string             `json:"storageEndpointSuffix"`
	CosmosDBDNSSuffix            string             `json:"cosmosDBDNSSuffix"`
	MariaDBDNSSuffix             string             `json:"mariaDBDNSSuffix"`
	MySQLDatabaseDNSSuffix       string             `json:"mySqlDatabaseDNSSuffix"`
	PostgresqlDatabaseDNSSuffix  string             `json:"postgresqlDatabaseDNSSuffix"`
	SQLDatabaseDNSSuffix         string             `json:"sqlDatabaseDNSSuffix"`
	TrafficManagerDNSSuffix      string             `json:"trafficManagerDNSSuffix"`
	KeyVaultDNSSuffix            string             `json:"keyVaultDNSSuffix"`
	ManagedHSMDNSSuffix          string             `json:"managedHSMDNSSuffix"`
	ServiceBusEndpointSuffix     string             `json:"serviceBusEndpointSuffix"`
	ServiceManagementVMDNSSuffix string             `json:"serviceManagementVMDNSSuffix"`
	ResourceManagerVMDNSSuffix   string             `json:"resourceManagerVMDNSSuffix"`
	ContainerRegistryDNSSuffix   string             `json:"containerRegistryDNSSuffix"`
	TokenAudience                string             `json:"tokenAudience"`
	APIManagementHostNameSuffix  string             `json:"apiManagementHostNameSuffix"`
	SynapseEndpointSuffix        string             `json:"synapseEndpointSuffix"`
	DatalakeSuffix               string             `json:"datalakeSuffix"`
	ResourceIdentifiers          ResourceIdentifier `json:"resourceIdentifiers"`
}

// PublicCloud is the default public Azure cloud environment
var PublicCloud = Environment{
	Name:                         "AzurePublicCloud",
	ManagementPortalURL:          "https://manage.windowsazure.com/",
	PublishSettingsURL:           "https://manage.windowsazure.com/publishsettings/index",
	ServiceManagementEndpoint:    "https://management.core.windows.net/",
	ResourceManagerEndpoint:      "https://management.azure.com/",
	ActiveDirectoryEndpoint:      "https://login.microsoftonline.com/",
	GalleryEndpoint:              "https://gallery.azure.com/",
	KeyVaultEndpoint:             "https://vault.azure.net/",
	ManagedHSMEndpoint:           "https://managedhsm.azure.net/",
	GraphEndpoint:                "https://graph.windows.net/",
	ServiceBusEndpoint:           "https://servicebus.windows.net/",
	BatchManagementEndpoint:      "https://batch.core.windows.net/",
	MicrosoftGraphEndpoint:       "https://graph.microsoft.com/",
	StorageEndpointSuffix:        "core.windows.net",
	CosmosDBDNSSuffix:            "documents.azure.com",
	MariaDBDNSSuffix:             "mariadb.database.azure.com",
	MySQLDatabaseDNSSuffix:       "mysql.database.azure.com",
	PostgresqlDatabaseDNSSuffix:  "postgres.database.azure.com",
	SQLDatabaseDNSSuffix:         "database.windows.net",
	TrafficManagerDNSSuffix:      "trafficmanager.net",
	KeyVaultDNSSuffix:            "vault.azure.net",
	ManagedHSMDNSSuffix:          "managedhsm.azure.net",
	ServiceBusEndpointSuffix:     "servicebus.windows.net",
	ServiceManagementVMDNSSuffix: "cloudapp.net",
	ResourceManagerVMDNSSuffix:   "cloudapp.azure.com",
	ContainerRegistryDNSSuffix:   "azurecr.io",
	TokenAudience:                "https://management.azure.com/",
	APIManagementHostNameSuffix:  "azure-api.net",
	SynapseEndpointSuffix:        "dev.azuresynapse.net",
	DatalakeSuffix:               "azuredatalakestore.net",
	ResourceIdentifiers: ResourceIdentifier{
		Graph:               "https://graph.windows.net/",
		KeyVault:            "https://vault.azure.net",
		Datalake:            "https://datalake.azure.net/",
		Batch:               "https://batch.core.windows.net/",
		OperationalInsights: "https://api.loganalytics.io",
		OSSRDBMS:            "https://ossrdbms-aad.database.windows.net",
		Storage:             "https://storage.azure.com/",
		Synapse:             "https://dev.azuresynapse.net",
		ServiceBus:          "https://servicebus.azure.net/",
		SQLDatabase:         "https://database.windows.net/",
		CosmosDB:            "https://cosmos.azure.com",
		ManagedHSM:          "https://managedhsm.azure.net",
		MicrosoftGraph:      "https://graph.microsoft.com/",
	},
}

// EnvironmentFromName returns an Environment based on the common name specified.
func EnvironmentFromName(name string) (Environment, error) {
	if strings.EqualFold(name, "AZURESTACKCLOUD") {
		return EnvironmentFromFile(os.Getenv(EnvironmentFilepathName))
	}

	name = strings.ToUpper(name)
	env, ok := environments[name]
	if !ok {
		return env, fmt.Errorf("error: there is no cloud environment matching the name %q", name)
	}

	return env, nil
}

// EnvironmentFromFile loads an Environment from a configuration file available on disk.
func EnvironmentFromFile(location string) (unmarshaled Environment, err error) {
	fileContents, err := ioutil.ReadFile(location)
	if err != nil {
		return
	}

	err = json.Unmarshal(fileContents, &unmarshaled)

	return
}
