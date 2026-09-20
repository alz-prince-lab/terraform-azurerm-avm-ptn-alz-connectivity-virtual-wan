locals {
  existing_firewall = one([
    for firewall in data.azapi_resource_list.firewalls.output.firewalls : firewall
    if lower(firewall.name) == lower(var.name)
  ])
  firewall_id = "${var.parent_id}/providers/Microsoft.Network/azureFirewalls/${var.name}"
  public_ip_association_parents = {
    for key, ip in data.azapi_resource.public_ips : key => try(
      provider::azapi::parse_resource_id("Microsoft.Network/azureFirewalls/azureFirewallIpConfigurations", ip.output.association).parent_id,
      provider::azapi::parse_resource_id("Microsoft.Network/azureFirewalls/ipConfigurations", ip.output.association).parent_id,
      ""
    )
  }
  public_ip_addresses = [
    for key in sort(keys(var.ip_configurations)) : data.azapi_resource.public_ips[key].output.address
  ]
  # Real Azure GETs for a multi-ipConfiguration Secured Virtual Hub firewall were observed (one firewall,
  # two ipConfigurations, api-version 2024-10-01, one region) to report privateIPAddress on exactly one
  # element and omit the key entirely (not null) on the other. In that single observation the address
  # happened to be on index 0, so a hardcoded [0] index returned the correct value there - this defect is
  # latent in that specific configuration, not actively triggered. Azure's return order was NOT measured to
  # be guaranteed to match declaration order, and misordering was NOT measured to occur either - neither
  # direction is asserted here. The only honest statement: if returned order ever differs from declared
  # order, `ipConfigurations[0]` reads an element whose privateIPAddress key may be absent, which either
  # silently returns the wrong (null) value or - as previously written - hard-fails with an opaque
  # `coalesce` error naming neither the firewall nor the actual cause. To remove the dependency on order
  # entirely, search every ipConfiguration for the one that actually carries the key, instead of assuming
  # position [0], and treat an empty-string privateIPAddress the same as an absent one (compact() drops
  # both null-coerced "" placeholders and genuine empty strings).
  ip_configuration_private_ip_addresses = compact([
    for configuration in try(azapi_resource.this.output.properties.ipConfigurations, []) :
    try(configuration.properties.privateIPAddress, "")
  ])
  virtual_hub = tolist([{
    virtual_hub_id = var.virtual_hub_id
    # Real Azure GETs for a Secured Virtual Hub firewall commonly leave properties.hubIPAddresses.privateIPAddress
    # null/absent even after a successful create (confirmed against a live customer-owned-IP firewall). The
    # authoritative private address is always present per-ipConfiguration instead, so fall back to that -
    # searching every ipConfiguration (see local.ip_configuration_private_ip_addresses above), not only the
    # first. If neither source resolves to a value, degrade to null here (via the outer try()) rather than
    # letting `coalesce` hard-fail with an opaque, unnamed error; azapi_resource.this's own postcondition in
    # main.tf independently re-derives this same outcome from self.output and raises a clear, named error
    # identifying the firewall if it is genuinely null, so this local never surfaces the raw coalesce error.
    private_ip_address = try(coalesce(
      try(azapi_resource.this.output.properties.hubIPAddresses.privateIPAddress, null),
      try(local.ip_configuration_private_ip_addresses[0], null)
    ), null)
    public_ip_count     = length(var.ip_configurations)
    public_ip_addresses = tolist(local.public_ip_addresses)
  }])
}
