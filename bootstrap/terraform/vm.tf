terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "3.29.1"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "2.30.0"
    }
  }
}

variable "ssh_public_key_path" {
  type        = string
  description = "Path to an SSH public key which should be used for authentication"
  default     = "~/.ssh/id_rsa.pub"
}

data "azurerm_client_config" "current" {}
provider "azuread" {}
provider "azurerm" {
  features {}
}

resource "azuread_application" "vault_azure_app" {
  display_name = "vault_azure_app"
}

resource "azuread_service_principal" "vault_azure_sp" {
  application_id = azuread_application.vault_azure_app.application_id
}

resource "azuread_service_principal_password" "vault_azure_sp_pwd" {
  service_principal_id = azuread_service_principal.vault_azure_sp.id
}

# Use system assigned managed identity
resource "azurerm_role_assignment" "vault_azure_msi_assignment" {
  role_definition_name = "Reader"
  scope                = azurerm_linux_virtual_machine.vault_azure_vm.id
  principal_id         = azurerm_linux_virtual_machine.vault_azure_vm.identity[0].principal_id
}

# Uncomment below for user assigned managed identity
resource "azurerm_user_assigned_identity" "vault_azure_uid" {
  name                = "vault_azure_uid"
  resource_group_name = azurerm_resource_group.vault_azure_rg.name
  location            = azurerm_resource_group.vault_azure_rg.location
}

resource "azurerm_role_assignment" "app_assignment_vm_read" {
  role_definition_name = "Reader"
  scope                = azurerm_linux_virtual_machine.vault_azure_vm.id
  principal_id         = azuread_service_principal.vault_azure_sp.object_id
}

resource "azurerm_resource_group" "vault_azure_rg" {
  name     = "vault_azure_rg"
  location = "westus2"
}

resource "azurerm_virtual_network" "vault_azure_vnet" {
  name                = "vault_azure_vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.vault_azure_rg.location
  resource_group_name = azurerm_resource_group.vault_azure_rg.name
}

resource "azurerm_subnet" "vault_azure_subnet" {
  name                 = "internal"
  resource_group_name  = azurerm_resource_group.vault_azure_rg.name
  virtual_network_name = azurerm_virtual_network.vault_azure_vnet.name
  address_prefixes     = ["10.0.2.0/24"]
}

resource "azurerm_network_interface" "vault_azure_nic" {
  name                = "vault_azure_nic"
  location            = azurerm_resource_group.vault_azure_rg.location
  resource_group_name = azurerm_resource_group.vault_azure_rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.vault_azure_subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.vault_azure_pub_ip.id
  }
}

resource "azurerm_public_ip" "vault_azure_pub_ip" {
  name                = "vault_azure_pub_ip"
  resource_group_name = azurerm_resource_group.vault_azure_rg.name
  location            = azurerm_resource_group.vault_azure_rg.location
  allocation_method   = "Static"
}

# Restrict SSH access to the local public IP
data "http" "my_ip" {
  url = "https://ifconfig.me/ip"
}

resource "azurerm_network_security_group" "vault_azure_sg" {
  name                = "vault_azure_sg"
  location            = azurerm_resource_group.vault_azure_rg.location
  resource_group_name = azurerm_resource_group.vault_azure_rg.name

  security_rule {
    name                       = "ssh"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = chomp(data.http.my_ip.body)
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_interface_security_group_association" "vault_azure_vm_sga" {
  network_interface_id      = azurerm_network_interface.vault_azure_nic.id
  network_security_group_id = azurerm_network_security_group.vault_azure_sg.id
}

resource "azurerm_linux_virtual_machine" "vault_azure_vm" {
  name                = "vault-azure-vm"
  resource_group_name = azurerm_resource_group.vault_azure_rg.name
  location            = azurerm_resource_group.vault_azure_rg.location
  size                = "Standard_F1"
  admin_username      = "adminuser"
  network_interface_ids = [
    azurerm_network_interface.vault_azure_nic.id,
  ]

  admin_ssh_key {
    username   = "adminuser"
    public_key = file(var.ssh_public_key_path)
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "18.04-LTS"
    version   = "latest"
  }

  identity {
    type = "SystemAssigned"

    # Uncomment below for user assigned managed identity
    # type = "UserAssigned"
    # identity_ids = [
    #  azurerm_user_assigned_identity.vault_azure_uid.id,
    # ]
  }
}

data "external" "access_token_jwt" {
  program = ["bash", "${path.root}/scripts/imds_access_token.sh"]
  query = {
    vm_ip_address = azurerm_public_ip.vault_azure_pub_ip.ip_address
  }

  depends_on = [azurerm_linux_virtual_machine.vault_azure_vm]
}

resource "local_file" "setup_environment_file" {
  filename = "local_environment_setup.sh"
  content  = <<EOF
export ACCESS_TOKEN_JWT=${data.external.access_token_jwt.result.access_token}
export VM_NAME=${azurerm_linux_virtual_machine.vault_azure_vm.name}
export VM_IP_ADDRESS=${azurerm_public_ip.vault_azure_pub_ip.ip_address}
export RESOURCE_GROUP_NAME=${azurerm_resource_group.vault_azure_rg.name}
export SUBSCRIPTION_ID=${data.azurerm_client_config.current.subscription_id}
export TENANT_ID=${data.azurerm_client_config.current.tenant_id}
export CLIENT_ID=${azuread_application.vault_azure_app.application_id}
export CLIENT_SECRET=${azuread_service_principal_password.vault_azure_sp_pwd.value}
EOF
}

output "access_token_jwt" {
  value     = data.external.access_token_jwt.result.access_token
  sensitive = true
}

output "vm_name" {
  value = azurerm_linux_virtual_machine.vault_azure_vm.name
}

output "vm_ip_address" {
  value = azurerm_public_ip.vault_azure_pub_ip.ip_address
}

output "resource_group_name" {
  value = azurerm_resource_group.vault_azure_rg.name
}

output "subscription_id" {
  value = data.azurerm_client_config.current.subscription_id
}

output "tenant_id" {
  value = data.azurerm_client_config.current.tenant_id
}

output "client_id" {
  value = azuread_application.vault_azure_app.application_id
}

output "client_secret" {
  value     = azuread_service_principal_password.vault_azure_sp_pwd.value
  sensitive = true
}