resource "azurerm_storage_account" "logs" {
  name                            = "privatelogsacct"
  resource_group_name             = "example-rg"
  location                        = "eastus"
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  public_network_access_enabled   = false
  min_tls_version                 = "TLS1_2"
}
