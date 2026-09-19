data "azapi_resource" "virtual_hub" {
  resource_id = var.virtual_hub_id
  type        = var.resource_types.network_virtual_hubs
  response_export_values = {
    location       = "location"
    virtual_wan_id = "properties.virtualWan.id"
  }
}

# The hub's own properties.sku is not reliably populated by the Virtual Hub RP; the
# Standard/Basic designation is authoritative only on the parent Virtual WAN's properties.type,
# which governs every hub attached to it.
data "azapi_resource" "virtual_wan" {
  resource_id = data.azapi_resource.virtual_hub.output.virtual_wan_id
  type        = var.resource_types.network_virtual_wans
  response_export_values = {
    type = "properties.type"
  }
}

data "azapi_resource_list" "firewalls" {
  parent_id = var.parent_id
  type      = var.resource_types.network_azure_firewalls
  response_export_values = {
    firewalls = "value[].{name:name,properties:properties}"
  }

  depends_on = [data.azapi_resource.virtual_hub]
}

data "azapi_resource" "public_ips" {
  for_each = var.ip_configurations

  resource_id = each.value.public_ip_address_id
  type        = var.resource_types.network_public_ip_addresses
  response_export_values = {
    address           = "properties.ipAddress"
    allocation_method = "properties.publicIPAllocationMethod"
    association       = "properties.ipConfiguration.id"
    ip_version        = "properties.publicIPAddressVersion"
    location          = "location"
    sku               = "sku.name"
    tier              = "sku.tier"
  }
}

resource "azapi_resource" "this" {
  location  = var.location
  name      = var.name
  parent_id = var.parent_id
  type      = var.resource_types.network_azure_firewalls
  body = {
    zones = sort([for zone in coalesce(var.zones, []) : tostring(zone)])
    properties = {
      sku = {
        name = "AZFW_Hub"
        tier = var.sku_tier
      }
      virtualHub = {
        id = var.virtual_hub_id
      }
      firewallPolicy  = var.firewall_policy_id == null ? null : { id = var.firewall_policy_id }
      threatIntelMode = "Alert"
      ipConfigurations = [
        for key in sort(keys(var.ip_configurations)) : {
          name = var.ip_configurations[key].name
          properties = {
            publicIPAddress = {
              id = var.ip_configurations[key].public_ip_address_id
            }
          }
        }
      ]
    }
  }
  ignore_body_changes = length(var.ignore_body_changes.network_azure_firewalls) > 0 ? var.ignore_body_changes.network_azure_firewalls : null
  replace_triggers_refs = [
    "properties.sku.name",
    "zones",
  ]
  response_export_values = [
    "properties.additionalProperties",
    "properties.firewallPolicy",
    "properties.hubIPAddresses",
    "properties.ipConfigurations",
    "properties.provisioningState",
    "properties.sku",
    "properties.threatIntelMode",
    "properties.virtualHub",
  ]
  retry                     = var.retry
  schema_validation_enabled = true
  tags                      = var.tags

  dynamic "timeouts" {
    for_each = var.timeouts == null ? [] : [var.timeouts]
    content {
      create = timeouts.value.create
      read   = timeouts.value.read
      update = timeouts.value.update
      delete = timeouts.value.delete
    }
  }

  lifecycle {
    precondition {
      condition = local.existing_firewall == null ? true : length([
        for configuration in try(coalesce(local.existing_firewall.properties.ipConfigurations, []), []) : configuration
        if try(configuration.properties.publicIPAddress.id, null) != null
      ]) > 0
      error_message = "An existing managed-IP firewall cannot be converted to customer IP mode by normal apply."
    }
    precondition {
      condition = lower(provider::azapi::parse_resource_id("Microsoft.Resources/resourceGroups", var.parent_id).subscription_id) == lower(
        provider::azapi::parse_resource_id("Microsoft.Network/virtualHubs", var.virtual_hub_id).subscription_id
      )
      error_message = "The firewall and virtual hub must be in the same subscription."
    }
    precondition {
      condition = data.azapi_resource.virtual_wan.output.type == "Standard" && (
        replace(lower(data.azapi_resource.virtual_hub.output.location), " ", "") == replace(lower(var.location), " ", "")
      )
      error_message = "A customer-IP firewall requires a Standard Virtual WAN hub in the same region."
    }
    precondition {
      condition = alltrue([
        for configuration in var.ip_configurations :
        lower(provider::azapi::parse_resource_id("Microsoft.Network/publicIPAddresses", configuration.public_ip_address_id).subscription_id) ==
        lower(provider::azapi::parse_resource_id("Microsoft.Resources/resourceGroups", var.parent_id).subscription_id)
      ])
      error_message = "Every customer public IP must be in the firewall's subscription."
    }
    precondition {
      condition = alltrue([
        for ip in data.azapi_resource.public_ips :
        ip.output.sku == "Standard" && ip.output.allocation_method == "Static" &&
        ip.output.ip_version == "IPv4" && ip.output.tier == "Regional" &&
        replace(lower(ip.output.location), " ", "") == replace(lower(var.location), " ", "")
      ])
      error_message = "Customer public IPs must be Standard/Regional, static IPv4 addresses in the firewall and hub region."
    }
    precondition {
      condition = alltrue([
        for key, ip in data.azapi_resource.public_ips : ip.output.association == null ? true : (
          lower(local.public_ip_association_parents[key]) == lower(local.firewall_id)
        )
      ])
      error_message = "A supplied public IP is associated with another resource. Only unassociated IPs or IPs already associated with this same firewall are accepted."
    }
  }
}

module "avm_interfaces" {
  source  = "Azure/avm-utl-interfaces/azure"
  version = "0.6.0"

  diagnostic_settings_v2 = {
    for key, setting in var.diagnostic_settings : key => merge(setting, {
      name = coalesce(setting.name, "diag-${var.name}")
    })
  }
  enable_telemetry                 = var.enable_telemetry
  lock                             = var.lock
  role_assignment_definition_scope = azapi_resource.this.id
  role_assignments                 = var.role_assignments
}

resource "azapi_resource" "diagnostic_settings" {
  for_each = var.diagnostic_settings

  name                      = coalesce(each.value.name, "diag-${var.name}")
  parent_id                 = azapi_resource.this.id
  type                      = var.resource_types.insights_diagnostic_settings
  body                      = module.avm_interfaces.diagnostic_settings_azapi_v2[each.key].body
  ignore_body_changes       = length(var.ignore_body_changes.insights_diagnostic_settings) > 0 ? var.ignore_body_changes.insights_diagnostic_settings : null
  response_export_values    = []
  retry                     = var.retry
  schema_validation_enabled = true

  dynamic "timeouts" {
    for_each = var.timeouts == null ? [] : [var.timeouts]
    content {
      create = timeouts.value.create
      read   = timeouts.value.read
      update = timeouts.value.update
      delete = timeouts.value.delete
    }
  }
}
