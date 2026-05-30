from dataclasses import dataclass


@dataclass
class AclEntry:
    action: str
    src: list[str]
    dst: list[str]


@dataclass
class Acl:
    acls: list[AclEntry]


def parse_acl(hujson: str) -> Acl:
    raise NotImplementedError
