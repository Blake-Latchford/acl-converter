from dataclasses import dataclass

from acl_converter.acl_parser import Acl, AclEntry


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
            if resolved_host != "*" and resolved_host != node_name:
                continue
            dport = "" if port == "*" else port
            for src in entry.src:
                resolved_src = acl.hosts.get(src, src)
                rules.append(FirewallRule(
                    type="in",
                    action="ACCEPT",
                    source="" if resolved_src == "*" else resolved_src,
                    dport=dport,
                ))
    return rules
