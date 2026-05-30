from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, AddressValueError

from acl_converter.acl_parser import Acl


@dataclass(frozen=True)
class FirewallRule:
    type: str      # "in" or "out"
    action: str    # "ACCEPT", "DROP", "REJECT"
    source: str = ""  # source address, empty means any (inbound)
    dest: str = ""    # dest address, empty means any (outbound)
    dport: str = ""   # destination port, empty means any
    proto: str = ""   # "tcp", "udp", empty means any


def generate_rules(acl: Acl, node_name: str) -> list[FirewallRule]:
    rules = []
    for entry in acl.acls:
        # Inbound: node matches a dst spec
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
                        proto=entry.proto,
                    ))

        # Outbound: node matches a src entry
        for src in entry.src:
            resolved_src = acl.hosts.get(src, src)
            if not _host_matches_node(resolved_src, node_name, acl):
                continue
            for dst_spec in entry.dst:
                host, port = dst_spec.rsplit(":", 1)
                resolved_host = acl.hosts.get(host, host)
                dests = acl.groups.get(resolved_host, [resolved_host])
                dport = "" if port == "*" else port
                for dest in dests:
                    rules.append(FirewallRule(
                        type="out",
                        action="ACCEPT",
                        dest="" if dest == "*" else dest,
                        dport=dport,
                        proto=entry.proto,
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
