# Scratch probe (not part of the required suite) requested by a parallel qualifier to
# check for a suspected region-list/BGP indexing failure when a nonzero-hub virtual_wan
# configuration mixes managed and customer public IP firewalls across multiple hubs,
# with zone-redundancy (availability_zones/regions module) engaged. This file exists
# only to reproduce (or rule out) the reported failure; see the qualification report
# for the classification (pre-existing vs candidate-introduced) once run.
mock_provider "modtm" {}
mock_provider "random" {}
mock_provider "azurerm" {
  mock_data "azurerm_client_config" {
    defaults = { subscription_id = "00000000-0000-0000-0000-000000000001" }
  }
  mock_resource "azurerm_virtual_hub" {
    defaults = { id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-test/providers/Microsoft.Network/virtualHubs/hub-test" }
  }
  mock_resource "azurerm_virtual_wan" {
    defaults = { id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-test/providers/Microsoft.Network/virtualWans/wan-test" }
  }
  mock_resource "azurerm_firewall_policy" {
    defaults = { id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-test/providers/Microsoft.Network/firewallPolicies/policy-test" }
  }
  mock_resource "azurerm_firewall" {
    defaults = {
      virtual_hub = {
        private_ip_address  = "10.0.0.4"
        public_ip_addresses = ["198.51.100.10"]
      }
    }
  }
}
mock_provider "azapi" {
  mock_data "azapi_resource_list" {
    defaults = { output = { firewalls = [] } }
  }
  mock_data "azapi_resource" {
    defaults = {
      output = {
        address        = "203.0.113.10", allocation_method = "Static", association = null
        ip_version     = "IPv4", location = "eastus", sku = "Standard", tier = "Regional", type = "Standard"
        virtual_wan_id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-test/providers/Microsoft.Network/virtualWans/wan-test"
        zones          = ["1", "2", "3"]
      }
    }
  }
  mock_resource "azapi_resource" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-test/providers/Microsoft.Network/azureFirewalls/fw-test"
      output = {
        properties = {
          hubIPAddresses = { privateIPAddress = "10.0.0.4" }, threatIntelMode = null, additionalProperties = {}
        }
      }
    }
  }
}

override_module {
  target  = module.regions
  outputs = { regions_by_name = { eastus = { zones = ["1", "2", "3"] }, westus = { zones = ["1", "2", "3"] } } }
}

variables {
  enable_telemetry     = false
  virtual_wan_settings = { enabled_resources = { ddos_protection_plan = false } }
  virtual_hubs = {
    hub_customer = {
      location          = "eastus"
      default_parent_id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-test"
      enabled_resources = {
        firewall                              = true, firewall_policy = false, bastion = false
        virtual_network_gateway_express_route = false, virtual_network_gateway_vpn = false
        private_dns_zones                     = false, private_dns_resolver = false, sidecar_virtual_network = false
      }
      firewall = {
        name               = "fw-customer"
        firewall_policy_id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-test/providers/Microsoft.Network/firewallPolicies/policy-test"
        ip_configurations = {
          primary = {
            name                 = "explicit-primary"
            public_ip_address_id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-ips/providers/Microsoft.Network/publicIPAddresses/pip-primary"
          }
        }
      }
    }
    hub_managed = {
      location          = "westus"
      default_parent_id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-test"
      enabled_resources = {
        firewall                              = true, firewall_policy = false, bastion = false
        virtual_network_gateway_express_route = false, virtual_network_gateway_vpn = false
        private_dns_zones                     = false, private_dns_resolver = false, sidecar_virtual_network = false
      }
      firewall = {
        name               = "fw-managed"
        firewall_policy_id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-test/providers/Microsoft.Network/firewallPolicies/policy-test"
      }
    }
  }
}

run "mixed_managed_and_customer_across_two_hubs_with_zones" {
  command = apply

  assert {
    condition     = output.firewall_public_ip_addresses["hub_customer"] == tolist(["203.0.113.10"])
    error_message = "The customer hub's public IP output must resolve without error alongside a managed hub."
  }
  assert {
    condition     = output.firewall_private_ip_address["hub_managed"] == "10.0.0.4"
    error_message = "The managed hub's private IP output must resolve without error alongside a customer hub."
  }
}

# Isolation case: BOTH hubs use customer-supplied public IPs (no managed firewall at all
# in this apply), to check whether the failure the other qualifier reported requires a
# managed firewall to be present at the same time, or is triggered by customer-mode alone
# once more than one zone-redundant hub is involved.
run "customer_only_across_two_hubs_with_zones" {
  command = apply

  variables {
    virtual_hubs = {
      hub_customer_a = {
        location          = "eastus"
        default_parent_id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-test"
        enabled_resources = {
          firewall                              = true, firewall_policy = false, bastion = false
          virtual_network_gateway_express_route = false, virtual_network_gateway_vpn = false
          private_dns_zones                     = false, private_dns_resolver = false, sidecar_virtual_network = false
        }
        firewall = {
          name               = "fw-customer-a"
          firewall_policy_id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-test/providers/Microsoft.Network/firewallPolicies/policy-test"
          ip_configurations = {
            primary = {
              name                 = "explicit-primary"
              public_ip_address_id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-ips/providers/Microsoft.Network/publicIPAddresses/pip-primary-a"
            }
          }
        }
      }
      hub_customer_b = {
        location          = "eastus"
        default_parent_id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-test"
        enabled_resources = {
          firewall                              = true, firewall_policy = false, bastion = false
          virtual_network_gateway_express_route = false, virtual_network_gateway_vpn = false
          private_dns_zones                     = false, private_dns_resolver = false, sidecar_virtual_network = false
        }
        firewall = {
          name               = "fw-customer-b"
          firewall_policy_id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-test/providers/Microsoft.Network/firewallPolicies/policy-test"
          ip_configurations = {
            primary = {
              name                 = "explicit-primary"
              public_ip_address_id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-ips/providers/Microsoft.Network/publicIPAddresses/pip-primary-b"
            }
          }
        }
      }
    }
  }

  assert {
    condition     = output.firewall_public_ip_addresses["hub_customer_a"] == tolist(["203.0.113.10"]) && output.firewall_public_ip_addresses["hub_customer_b"] == tolist(["203.0.113.10"])
    error_message = "Both customer-only hubs must resolve their public IP outputs without any region-list/index error."
  }
}

# Isolation case: BOTH hubs use managed (module-provisioned) public IPs, to establish the
# pre-existing (non-customer-IP) baseline behavior for the same two-region, zone-redundant
# shape, for direct comparison against the mixed and customer-only cases above.
run "managed_only_across_two_hubs_with_zones" {
  command = apply

  variables {
    virtual_hubs = {
      hub_managed_a = {
        location          = "eastus"
        default_parent_id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-test"
        enabled_resources = {
          firewall                              = true, firewall_policy = false, bastion = false
          virtual_network_gateway_express_route = false, virtual_network_gateway_vpn = false
          private_dns_zones                     = false, private_dns_resolver = false, sidecar_virtual_network = false
        }
        firewall = {
          name               = "fw-managed-a"
          firewall_policy_id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-test/providers/Microsoft.Network/firewallPolicies/policy-test"
        }
      }
      hub_managed_b = {
        location          = "westus"
        default_parent_id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-test"
        enabled_resources = {
          firewall                              = true, firewall_policy = false, bastion = false
          virtual_network_gateway_express_route = false, virtual_network_gateway_vpn = false
          private_dns_zones                     = false, private_dns_resolver = false, sidecar_virtual_network = false
        }
        firewall = {
          name               = "fw-managed-b"
          firewall_policy_id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-test/providers/Microsoft.Network/firewallPolicies/policy-test"
        }
      }
    }
  }

  assert {
    condition     = output.firewall_private_ip_address["hub_managed_a"] == "10.0.0.4" && output.firewall_private_ip_address["hub_managed_b"] == "10.0.0.4"
    error_message = "Both managed-only hubs must resolve their private IP outputs without any region-list/index error (pre-existing baseline behavior)."
  }
}
