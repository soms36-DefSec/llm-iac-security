resource "azurerm_storage_account" "logs" {
  name                            = "publiclogsacct"
  resource_group_name             = "example-rg"
  location                        = "eastus"
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  public_network_access_enabled   = true
  min_tls_version                 = "TLS1_0"
}
