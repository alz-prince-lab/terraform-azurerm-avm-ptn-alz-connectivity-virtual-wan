# RELEASE QUALIFICATION FIX (issue #352 offline review) - authorized bounded correction for a confirmed
# ownership-check gap.
#
# BEFORE this commit's implementation change, the public-IP ownership precondition in main.tf inspected only
# `properties.ipConfiguration.id` (aliased `association`) and never `properties.natGateway.id`. A public IP
# actively attached to a NAT Gateway presents `ipConfiguration = null` while `natGateway` is non-null, and
# was therefore silently treated as "unowned" and adopted into this firewall's configuration - a false
# negative on ownership. This file's first run below is written RED-first: it asserts REJECTION of that
# exact shape and is expected to FAIL against the pre-fix implementation (which accepts it). See the release
# qualification report's defects section for the full write-up and the fix authorization.
#
# API version verified before writing the fix: Microsoft.Network/publicIPAddresses@2024-10-01 (this
# module's `network_public_ip_addresses` default resource type - see variables.tf). The ARM template
# reference for that exact API version (learn.microsoft.com/azure/templates/microsoft.network/2024-10-01/
# publicipaddresses) confirms `natGateway` (type `NatGateway`, a `{id: string}` reference) is a top-level
# sibling of `ipConfiguration` (type `IPConfiguration`, also a `{id: string}` reference; omitted from the ARM
# template's PUT-body property table because it is response-only/read-only, but present on every GET - the
# SDK model docs for `PublicIPAddressPropertiesFormat` confirm the `ipConfiguration` property exists at this
# schema). There is no separate `natRule`/`natRules` or `loadBalancerBackendAddressPools` property directly
# on the `Microsoft.Network/publicIPAddresses` resource at this API version: a load-balancer/NAT-rule
# attachment surfaces through `ipConfiguration` pointing at the load balancer's own frontend IP
# configuration resource ID, which the pre-existing association-parent check already rejects (it cannot be
# parsed as an Azure Firewall ID) - so NAT Gateway is the one distinct, previously-blind association surface
# that needed an explicit additional field read and check.
#
# This file supersedes the earlier "ownership_association_gap.tftest.hcl" probe (deleted in this commit),
# which only documented the gap by asserting the buggy acceptance as current behavior. The equivalent
# scenario is now asserted as a rejection instead.
mock_provider "modtm" {}
mock_provider "random" {}
mock_provider "azapi" {
  mock_data "azapi_resource_list" {
    defaults = { output = { firewalls = [], results = [] } }
  }
  mock_data "azapi_resource" {
    defaults = {
      output = {
        address        = "203.0.113.10", allocation_method = "Static", association = null, nat_gateway = null
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

# NEGATIVE (the confirmed gap): a public IP with ipConfiguration null but natGateway non-null must be
# rejected, not silently adopted. RED before the fix in this commit; GREEN after it.
run "reject_natgateway_associated_public_ip" {
  command = plan
  override_data {
    target = data.azapi_resource.public_ips["primary"]
    values = {
      output = {
        address     = "203.0.113.10", allocation_method = "Static", association = null
        ip_version  = "IPv4", location = "eastus", sku = "Standard", tier = "Regional"
        nat_gateway = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-test/providers/Microsoft.Network/natGateways/natgw-test"
        zones       = ["1", "2", "3"]
      }
    }
  }
  expect_failures = [azapi_resource.this]
}

# POSITIVE (must not regress): a fully detached public IP - ipConfiguration null AND natGateway null - must
# still be accepted unconditionally.
run "accept_fully_detached_public_ip" {
  command = apply
  override_data {
    target = data.azapi_resource.public_ips["primary"]
    values = {
      output = {
        address     = "203.0.113.10", allocation_method = "Static", association = null
        ip_version  = "IPv4", location = "eastus", sku = "Standard", tier = "Regional"
        nat_gateway = null
        zones       = ["1", "2", "3"]
      }
    }
  }
  assert {
    condition     = length(azapi_resource.this.body.properties.ipConfigurations) == 1
    error_message = "A fully detached public IP (no ipConfiguration, no natGateway) must remain acceptable after the ownership-check fix."
  }
}

# POSITIVE (must not regress idempotency): a public IP already associated with THIS SAME firewall's own IP
# configuration (the reconcile/no-op re-apply case) must still be accepted, even though this is a real,
# non-null association - and even with an explicit natGateway = null alongside it.
run "accept_reconciliation_of_ip_already_owned_by_this_firewall" {
  command = apply
  override_data {
    target = data.azapi_resource.public_ips["primary"]
    values = {
      output = {
        address           = "203.0.113.10"
        allocation_method = "Static"
        association       = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-test/providers/Microsoft.Network/azureFirewalls/fw-test/azureFirewallIpConfigurations/internet-primary"
        ip_version        = "IPv4", location = "eastus", sku = "Standard", tier = "Regional"
        nat_gateway       = null
        zones             = ["1", "2", "3"]
      }
    }
  }
  assert {
    condition     = length(azapi_resource.this.body.properties.ipConfigurations) == 1
    error_message = "Idempotent reconciliation of a public IP already attached to this same firewall must not regress after the NAT Gateway ownership fix."
  }
}

# NEGATIVE, multi-IP: with two customer IPs, one free and one NAT-Gateway-owned, the whole apply must still
# be rejected (not just silently drop/ignore the bad one) - proves the fix's alltrue() semantics correctly
# fail the precondition even when a legitimate IP is mixed in alongside the offending one.
run "reject_mixed_free_and_natgateway_owned_ips" {
  command = plan
  variables {
    ip_configurations = {
      free_ip = {
        name                 = "internet-free"
        public_ip_address_id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-ips/providers/Microsoft.Network/publicIPAddresses/pip-free"
      }
      natgw_owned_ip = {
        name                 = "internet-natgw"
        public_ip_address_id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-ips/providers/Microsoft.Network/publicIPAddresses/pip-natgw-owned"
      }
    }
  }
  override_data {
    target = data.azapi_resource.public_ips["free_ip"]
    values = {
      output = {
        address     = "203.0.113.20", allocation_method = "Static", association = null
        ip_version  = "IPv4", location = "eastus", sku = "Standard", tier = "Regional"
        nat_gateway = null
        zones       = ["1", "2", "3"]
      }
    }
  }
  override_data {
    target = data.azapi_resource.public_ips["natgw_owned_ip"]
    values = {
      output = {
        address     = "203.0.113.21", allocation_method = "Static", association = null
        ip_version  = "IPv4", location = "eastus", sku = "Standard", tier = "Regional"
        nat_gateway = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-test/providers/Microsoft.Network/natGateways/natgw-test"
        zones       = ["1", "2", "3"]
      }
    }
  }
  expect_failures = [azapi_resource.this]
}

# Computed-ID timing (see release qualification report §5A/§6 for full discussion): `public_ip_address_id`
# is documented (see variables.tf) as "may be unknown until apply". A `terraform test` `.tftest.hcl` file
# cannot itself declare an independent resource to manufacture a genuinely unknown-until-apply value for a
# `command = plan` run against this submodule in isolation (there is no upstream resource in this test file
# to be unknown from) - a faithful reproduction would require either a real `azapi_resource` apply in a
# prior run (which stops being "unknown" once test-applied) or exercising this from a calling context that
# has a genuinely not-yet-applied upstream resource, which is exactly the shape the root-level
# `tests/unit/Test-FirewallGraph.ps1` harness's `customer_unknown` and `customer_deferred` cases already
# exercise (a genuinely unknown/deferred public IP identity flowing into this submodule from the graph
# fixtures, checked against the mode-lock postcondition). No dedicated test was added here asserting the
# ownership precondition's specific behavior under an unknown ID; that exact combination remains unverified
# offline and is listed as a "missing live gate" in the release qualification report rather than claimed as
# covered.
