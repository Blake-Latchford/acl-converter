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
            if host != "*" and host != node_name:
                continue
            dport = "" if port == "*" else port
            for src in entry.src:
                rules.append(FirewallRule(
                    type="in",
                    action="ACCEPT",
                    source="" if src == "*" else src,
                    dport=dport,
                ))
    return rules
