locals {
  # Unknown discovery deliberately makes customer cardinality unplannable, before a legacy instance can be destroyed.
  customer_firewalls = {
    for key, firewall in local.requested_customer_firewalls : key => firewall
    if contains(["absent", "managed", "customer"], local.existing_public_ip_modes[key])
  }
  customer_mode = { for key, firewall in local.firewalls : key => length(firewall.ip_configurations) > 0 }
  diagnostic_settings_v2 = {
    for key, setting in local.flattened_diagnostic_settings : key => {
      name = coalesce(setting.data.name, "diag-${local.firewalls[setting.virtual_hub_key].name}")
      logs = concat(
        [for category in setting.data.log_categories : { category = category, category_group = null }],
        [for group in setting.data.log_groups : { category = null, category_group = group }]
      )
      metrics                                  = [for category in setting.data.metric_categories : { category = category }]
      log_analytics_destination_type           = setting.data.log_analytics_destination_type
      workspace_resource_id                    = setting.data.workspace_resource_id
      storage_account_resource_id              = setting.data.storage_account_resource_id
      event_hub_authorization_rule_resource_id = setting.data.event_hub_authorization_rule_resource_id
      event_hub_name                           = setting.data.event_hub_name
      marketplace_partner_resource_id          = setting.data.marketplace_partner_resource_id
    }
  }
  existing_customer_mode = {
    for key, firewall in local.existing_firewalls : key => length([
      for configuration in try(coalesce(firewall.properties.ipConfigurations, []), []) : configuration
      if try(configuration.properties.publicIPAddress.id, null) != null
    ]) > 0
  }
  existing_firewalls = {
    for key, firewall in local.requested_customer_firewalls : key => one([
      for existing in local.existing_firewalls_by_name[key] : existing
      if lower(provider::azapi::parse_resource_id("Microsoft.Network/azureFirewalls", existing.id).resource_group_name) == lower(firewall.resource_group_name)
    ])
  }
  existing_firewalls_by_name = {
    for key, firewall in local.requested_customer_firewalls : key => [
      for existing in one(data.azapi_resource_list.firewalls).output.firewalls : existing
      if lower(existing.name) == lower(firewall.name)
    ]
  }
  existing_public_ip_modes = {
    for key, firewall in local.existing_firewalls : key =>
    firewall == null ? "absent" : local.existing_customer_mode[key] ? "customer" : "managed"
  }
  firewalls = var.firewalls == null ? {} : var.firewalls
  flattened_diagnostic_settings = {
    for item in flatten([
      for hub_key, settings in var.diagnostic_settings : [
        for setting_key, setting in settings : {
          key             = "${hub_key}-${setting_key}"
          virtual_hub_key = hub_key
          data            = setting
        }
      ]
      ]) : item.key => {
      virtual_hub_key = item.virtual_hub_key
      data            = item.data
    }
  }
  parent_ids = {
    for key, firewall in local.requested_customer_firewalls : key =>
    "/subscriptions/${one(data.azurerm_client_config.current).subscription_id}/resourceGroups/${firewall.resource_group_name}"
  }
  requested_customer_firewalls = { for key, firewall in local.firewalls : key => firewall if local.customer_mode[key] }
  resource_objects = merge(
    azurerm_firewall.fw,
    { for key, firewall in module.customer_firewalls : key => firewall.legacy_resource }
  )
}
