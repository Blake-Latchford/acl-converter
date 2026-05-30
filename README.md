# acl-converter

An Ansible plugin that reads a [Tailscale](https://tailscale.com/) ACL policy file (HuJSON format) and generates host-based firewall rules from it.

## Why

Tailscale ACLs define which nodes can reach which ports across your tailnet. But those policies live in Tailscale's control plane — if you also want to enforce equivalent rules at the Linux host firewall (iptables, nftables, firewalld, etc.), you'd normally have to maintain two separate policy sources that can drift out of sync.

This plugin treats the Tailscale ACL file as the single source of truth and derives firewall rules from it automatically.

## How it works

1. Parse the Tailscale HuJSON ACL file (strips comments, handles trailing commas).
2. Resolve group and tag aliases defined in the policy.
3. Emit firewall rules corresponding to each `acl` entry — one rule per `src`/`dst`/`ports` combination.
4. Apply them via your chosen firewall backend.

## Requirements

- Ansible >= 2.14
- Python >= 3.10 on the controller
- A Tailscale ACL file (local path or fetched from the Tailscale API)

## Installation
```bash
git clone https://github.com/Blake-Latchford/acl-converter.git
cd acl-converter
ansible-galaxy collection build
ansible-galaxy collection install acl_converter-*.tar.gz
```

## Usage

### Module: `acl_converter`

```yaml
- name: Apply Tailscale ACL as host firewall rules
  acl_converter.acl_converter:
    acl_file: /etc/tailscale/acls.hujson
    backend: nftables       # iptables | nftables | firewalld | ufw
    tailscale_node: "{{ inventory_hostname }}"
    state: present
```

### Fetching the ACL from the Tailscale API

```yaml
- name: Fetch current ACL from Tailscale API
  acl_converter.acl_fetch:
    api_key: "{{ tailscale_api_key }}"
    tailnet: example.com
  register: acl

- name: Apply rules
  acl_converter.acl_converter:
    acl_content: "{{ acl.content }}"
    backend: nftables
    tailscale_node: "{{ inventory_hostname }}"
    state: present
```

## Module parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `acl_file` | no | — | Path to a local HuJSON ACL file |
| `acl_content` | no | — | Raw HuJSON string (alternative to `acl_file`) |
| `backend` | no | `nftables` | Firewall backend: `iptables`, `nftables`, `firewalld`, `ufw` |
| `tailscale_node` | yes | — | Hostname or Tailscale node name to filter rules for |
| `state` | no | `present` | `present` to apply rules, `absent` to remove them |
| `purge` | no | `false` | Remove rules not covered by the current ACL |

## Tailscale ACL format

The plugin understands the standard Tailscale HuJSON ACL fields:

- `hosts` — named host aliases
- `groups` — named groups of users/nodes
- `tagOwners` — tag definitions
- `acls` — the actual allow rules (`action`, `src`, `dst`, `ports`)

HuJSON extensions (C-style comments `//`, `/* */` and trailing commas) are supported.

## Example

Given an ACL entry:

```jsonc
{
  "acls": [
    {
      "action": "accept",
      "src": ["tag:web"],
      "dst": ["tag:db:5432"]
    }
  ]
}
```

The plugin emits an nftables rule that allows TCP port 5432 from any node tagged `web` to any node tagged `db`.

## License

MIT — see [LICENSE](LICENSE).
