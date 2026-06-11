resource "azurerm_key_vault" "main" {
  name                          = "public-kv"
  location                      = "eastus"
  resource_group_name           = "example-rg"
  tenant_id                     = "00000000-0000-0000-0000-000000000000"
  sku_name                      = "standard"
  purge_protection_enabled      = false
  public_network_access_enabled = true
}
