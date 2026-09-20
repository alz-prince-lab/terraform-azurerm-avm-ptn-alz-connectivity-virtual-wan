mock_provider "modtm" {}
mock_provider "random" {}
mock_provider "azapi" {
  mock_data "azapi_resource_list" {
    defaults = { output = { firewalls = [], results = [] } }
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
}

variables {
  enable_telemetry = false
  name             = "fw-test"
  parent_id        = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-test"
  location         = "eastus"
  virtual_hub_id   = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-test/providers/Microsoft.Network/virtualHubs/hub-test"
  ip_configurations = {
    primary = {
      name                 = "internet-primary"
      public_ip_address_id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-ips/providers/Microsoft.Network/publicIPAddresses/pip-primary"
    }
    secondary = {
      name                 = "internet-secondary"
      public_ip_address_id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-ips/providers/Microsoft.Network/publicIPAddresses/pip-secondary"
    }
  }
}

# Regression coverage for a real-Azure finding: local.virtual_hub[0].private_ip_address previously hardcoded
# properties.ipConfigurations[0], an unsafe index. ARM does not guarantee ipConfigurations array order
# matches submission order, and classic Azure Firewall semantics put the private address on a single
# ipConfiguration, not necessarily the first one. Before the fix, if index 0 lacked privateIPAddress but a
# later index had it, the expression did NOT degrade to null - it hard-failed with an opaque
# `Call to function "coalesce" failed: no non-null, non-empty-string arguments.` error naming neither the
# firewall nor the cause, even though the private IP address was genuinely available at another index.
#
# This is the only run in this file that applies azapi_resource.this, so its override_resource output is
# guaranteed authoritative and not shadowed by state accumulated from an earlier run in the same file (see
# real_azure_optional_response_properties.tftest.hcl for the same convention/rationale).
#
# RED (before the fix): this run fails during apply with the opaque coalesce error above, even though
# ipConfigurations[1] plainly carries a usable private IP address.
# GREEN (after the fix): the module searches every ipConfiguration, not only index 0, and this run passes.
run "resolves_private_ip_from_non_first_ip_configuration" {
  command = apply
  override_resource {
    target = azapi_resource.this
    values = {
      output = {
        properties = {
          additionalProperties = {}
          ipConfigurations = [
            {
              name = "internet-primary"
              properties = {
                # index 0 genuinely lacks a private IP in this Azure response shape (key absent), per the
                # real-Azure finding this test reproduces.
                publicIPAddress = { id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-ips/providers/Microsoft.Network/publicIPAddresses/pip-primary" }
              }
            },
            {
              name = "internet-secondary"
              properties = {
                privateIPAddress = "10.224.8.133"
                publicIPAddress  = { id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-ips/providers/Microsoft.Network/publicIPAddresses/pip-secondary" }
              }
            }
          ]
        }
      }
    }
  }
  assert {
    condition     = output.private_ip_address == "10.224.8.133"
    error_message = "The private IP address is genuinely present on a later ipConfiguration element; a hardcoded index-0 lookup must not hard-fail or silently miss it."
  }
}
