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
  virtual_hub = tolist([{
    virtual_hub_id = var.virtual_hub_id
    # Real Azure GETs for a Secured Virtual Hub firewall commonly leave properties.hubIPAddresses.privateIPAddress
    # null/absent even after a successful create (confirmed against a live customer-owned-IP firewall). The
    # authoritative private address is always present per-ipConfiguration instead, so fall back to that.
    private_ip_address = coalesce(
      try(azapi_resource.this.output.properties.hubIPAddresses.privateIPAddress, null),
      try(azapi_resource.this.output.properties.ipConfigurations[0].properties.privateIPAddress, null)
    )
    public_ip_count     = length(var.ip_configurations)
    public_ip_addresses = tolist(local.public_ip_addresses)
  }])
}
