from dataclasses import dataclass

from acl_converter.acl_parser import Acl, AclEntry


@dataclass(frozen=True)
class FirewallRule:
    type: str    # "in" or "out"
    action: str  # "ACCEPT", "DROP", "REJECT"
    source: str  # empty string means any
    dport: str   # empty string means any


def generate_rules(acl: Acl, node_name: str) -> list[FirewallRule]:
    raise NotImplementedError
