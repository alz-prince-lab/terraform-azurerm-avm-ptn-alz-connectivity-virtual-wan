# RELEASE QUALIFICATION PROBE (issue #352 offline review) - documents current behavior only.
#
# The public-IP ownership/association check in main.tf is:
#
#   data "azapi_resource" "public_ips" {
#     ...
#     response_export_values = {
#       address           = "properties.ipAddress"
#       allocation_method = "properties.publicIPAllocationMethod"
#       association       = "properties.ipConfiguration.id"
#       ip_version        = "properties.publicIPAddressVersion"
#       location          = "location"
#       sku               = "sku.name"
#       tier              = "sku.tier"
#       zones             = "zones"
#     }
#   }
#
#   precondition {
#     condition = alltrue([
#       for key, ip in data.azapi_resource.public_ips : ip.output.association == null ? true : (
#         lower(local.public_ip_association_parents[key]) == lower(local.firewall_id)
#       )
#     ])
#     error_message = "A supplied public IP is associated with another resource. Only unassociated IPs or IPs
#     already associated with this same firewall are accepted."
#   }
#
# The data source's response_export_values requests ONLY `properties.ipConfiguration.id` (aliased to
# `association`). It never requests `properties.natGateway`, any `properties.natRule`/`natRules` reference,
# or `properties.ipConfiguration.loadBalancerBackendAddressPools` (or any other association surface on a
# Microsoft.Network/publicIPAddresses resource). The ownership precondition then treats `association == null`
# as unconditionally "unowned/available" - regardless of whether the real PIP is actively attached to a NAT
# Gateway (where `properties.ipConfiguration` is null but `properties.natGateway` is non-null) or anything
# else the module never reads.
#
# This is a genuine false-negative ownership gap, not merely an ambiguous/live-Azure question like the zone
# gap documented in zone_compatibility_gap.tftest.hcl: a real NAT-Gateway-attached PIP would be silently
# accepted as available and reassigned to this firewall.
#
# This test does NOT change the implementation. It only proves, with a mocked PIP whose `association` is
# null (the exact shape the module would see for a NAT-Gateway-attached IP, since it never queries
# `natGateway` at all), that the module's own precondition currently passes such a PIP through unconditionally.
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
  }
}

# KNOWN GAP (documented, not fixed here): a public IP whose `ipConfiguration` is null - the exact shape a
# real NAT-Gateway-attached PIP would have, since `properties.natGateway` is never read by this module at
# all - is accepted as "unowned" by the precondition and adopted into this firewall's configuration.
run "current_behavior_accepts_ip_configuration_null_association_unconditionally" {
  command = apply
  override_data {
    target = data.azapi_resource.public_ips["primary"]
    values = {
      output = {
        address    = "203.0.113.10", allocation_method = "Static", association = null
        ip_version = "IPv4", location = "eastus", sku = "Standard", tier = "Regional"
        zones      = ["1", "2", "3"]
        # Real Azure would also populate properties.natGateway (and possibly properties.natRule/
        # loadBalancerBackendAddressPools) on a PIP actually attached to a NAT Gateway. This module's
        # data source never requests any of those fields, so there is no way for this mock - or the real
        # module - to see them; only `association` (from properties.ipConfiguration.id) is inspected.
      }
    }
  }
  assert {
    condition     = length(azapi_resource.this.body.properties.ipConfigurations) == 1
    error_message = "Current behavior (documented gap, not a fix): the module accepts and adopts a public IP whose ipConfiguration association is null unconditionally, without inspecting properties.natGateway (or any other association surface) at all. A PIP genuinely attached to a NAT Gateway would present exactly this same null-ipConfiguration shape and would be silently treated as available. See the KNOWN GAP comment at the top of this file and the release qualification report's defects section for the proposed bounded fix, which requires implementation-owner authorization before being built."
  }
}
