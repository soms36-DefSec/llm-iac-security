resource "azurerm_network_security_group" "web" {
  name                = "web-nsg"
  location            = "eastus"
  resource_group_name = "example-rg"

  security_rule {
    name                       = "ssh-private"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "10.0.0.0/24"
    destination_address_prefix = "*"
  }
}
