# acl-converter

A Terraform [external data source](https://registry.terraform.io/providers/hashicorp/external/latest/docs/data-sources/external) script that reads a [Tailscale](https://tailscale.com/) ACL policy file (HuJSON format) and returns firewall rules for a given node, ready to feed into [`proxmox_virtual_environment_firewall_rules`](https://registry.terraform.io/providers/bpg/proxmox/latest/docs/resources/virtual_environment_firewall_rules).

## Why

Tailscale ACLs define which nodes can reach which ports across your tailnet. Rather than maintaining a separate firewall policy that can drift out of sync, this script treats the Tailscale ACL file as the single source of truth and derives Proxmox firewall rules from it at `terraform plan` time.

## Requirements

- Python >= 3.10
- [`hjson`](https://pypi.org/project/hjson/) (`pip install -r requirements.txt`)

## Usage

```hcl
data "external" "acl_rules" {
  for_each = var.vms

  program = ["python3", "${path.module}/acl_converter/main.py"]
  query = {
    acl_file  = var.tailscale_acl_file
    node_name = each.value.name
  }
}

resource "proxmox_virtual_environment_firewall_rules" "vm" {
  for_each = var.vms

  node_name = each.value.proxmox_node
  vm_id     = each.value.vm_id

  dynamic "rule" {
    for_each = jsondecode(data.external.acl_rules[each.key].result.rules)
    content {
      type    = rule.value.type
      action  = rule.value.action
      source  = rule.value.source
      dport   = rule.value.dport
      enabled = true
    }
  }
}
```

## Interface

**stdin** — JSON query object:

```json
{
  "acl_file": "/path/to/acls.hujson",
  "node_name": "my-vm"
}
```

**stdout** — flat JSON map (Terraform `external` requirement); rules are JSON-encoded as a string:

```json
{
  "rules": "[{\"type\":\"in\",\"action\":\"ACCEPT\",\"source\":\"10.0.0.1\",\"dport\":\"5432\"}]"
}
```

## Tailscale ACL format

The script understands the standard Tailscale HuJSON ACL fields:

- `hosts` — named host aliases
- `groups` — named groups of users/nodes
- `tagOwners` — tag definitions
- `acls` — the actual allow rules (`action`, `src`, `dst`)

HuJSON extensions (C-style comments `//`, `/* */` and trailing commas) are supported.

## TODO

### CIDR matching
- [ ] Match node IP against CIDR ranges in `dst`
- [ ] Match node IP against CIDR ranges in `src`

### Other
- [ ] `proto` field on firewall rules (ACL entries can specify `tcp`/`udp`)
- [ ] Outbound rules (node appears as `src`, generate `type: out` rules)
- [ ] `tagOwners` / tag membership resolution

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest
```

## License

MIT — see [LICENSE](LICENSE).
