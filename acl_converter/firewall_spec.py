from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, AddressValueError

from acl_converter.acl_parser import Acl, AclEntry


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
        rules.extend(_inbound_rules(acl, entry, node_name))
        rules.extend(_outbound_rules(acl, entry, node_name))
    # Use a dict with empty values here to preserve order.
    return list(dict.fromkeys(rules))


def _inbound_rules(acl: Acl, entry: AclEntry, node_name: str) -> list[FirewallRule]:
    rules = []
    for dst_spec in entry.dst:
        host, dport = _parse_dst_spec(dst_spec)
        resolved_host = acl.hosts.get(host, host)
        if not _host_matches_node(resolved_host, node_name, acl):
            continue
        for source in _expand_src(acl, entry.src):
            rules.append(FirewallRule(type="in", action="ACCEPT", source=source, dport=dport, proto=entry.proto))
    return rules


def _outbound_rules(acl: Acl, entry: AclEntry, node_name: str) -> list[FirewallRule]:
    rules = []
    for src in entry.src:
        resolved_src = acl.hosts.get(src, src)
        if not _host_matches_node(resolved_src, node_name, acl):
            continue
        for dest, dport in _expand_dst(acl, entry.dst):
            rules.append(FirewallRule(type="out", action="ACCEPT", dest=dest, dport=dport, proto=entry.proto))
    return rules


def _parse_dst_spec(dst_spec: str) -> tuple[str, str]:
    host, port = dst_spec.rsplit(":", 1)
    return host, "" if port == "*" else port


def _expand_src(acl: Acl, srcs: list[str]) -> list[str]:
    sources = []
    for src in srcs:
        resolved = acl.hosts.get(src, src)
        members = acl.groups.get(resolved, [resolved])
        sources.extend("" if m == "*" else m for m in members)
    return sources


def _expand_dst(acl: Acl, dst_specs: list[str]) -> list[tuple[str, str]]:
    results = []
    for dst_spec in dst_specs:
        host, dport = _parse_dst_spec(dst_spec)
        resolved = acl.hosts.get(host, host)
        members = acl.groups.get(resolved, [resolved])
        results.extend(("" if m == "*" else m, dport) for m in members)
    return results


def _host_matches_node(host: str, node_name: str, acl: Acl) -> bool:
    if host == "*":
        return True
    if host in acl.groups:
        return node_name in acl.groups[host]
    try:
        return IPv4Address(node_name) in IPv4Network(host, strict=False)
    except (AddressValueError, ValueError):
        return host == node_name
