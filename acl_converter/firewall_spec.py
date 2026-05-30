from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, AddressValueError

from acl_converter.acl_parser import Acl


@dataclass(frozen=True)
class FirewallRule:
    type: str    # "in" or "out"
    action: str  # "ACCEPT", "DROP", "REJECT"
    source: str  # empty string means any
    dport: str   # empty string means any


def generate_rules(acl: Acl, node_name: str) -> list[FirewallRule]:
    rules = []
    for entry in acl.acls:
        for dst_spec in entry.dst:
            host, port = dst_spec.rsplit(":", 1)
            resolved_host = acl.hosts.get(host, host)
            if not _host_matches_node(resolved_host, node_name, acl):
                continue
            dport = "" if port == "*" else port
            for src in entry.src:
                resolved_src = acl.hosts.get(src, src)
                sources = acl.groups.get(resolved_src, [resolved_src])
                for source in sources:
                    rules.append(FirewallRule(
                        type="in",
                        action="ACCEPT",
                        source="" if source == "*" else source,
                        dport=dport,
                    ))
    return rules


def _host_matches_node(host: str, node_name: str, acl: Acl) -> bool:
    if host == "*":
        return True
    if host in acl.groups:
        return node_name in acl.groups[host]
    try:
        return IPv4Address(node_name) in IPv4Network(host, strict=False)
    except (AddressValueError, ValueError):
        return host == node_name
