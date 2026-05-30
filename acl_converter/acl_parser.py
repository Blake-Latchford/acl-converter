from dataclasses import dataclass, field

import hjson


@dataclass
class AclEntry:
    action: str
    src: list[str]
    dst: list[str]


@dataclass
class Acl:
    hosts: dict[str, str] = field(default_factory=dict)
    groups: dict[str, list[str]] = field(default_factory=dict)
    acls: list[AclEntry] = field(default_factory=list)


def parse_acl(hujson: str) -> Acl:
    data = hjson.loads(hujson)
    if not isinstance(data, dict):
        raise ValueError("ACL must be a JSON object")

    return Acl(
        hosts=data.get("hosts", {}),
        groups=data.get("groups", {}),
        acls=[_parse_entry(i, e) for i, e in enumerate(data.get("acls", []))],
    )


def _parse_entry(index: int, entry) -> AclEntry:
    try:
        return AclEntry(
            action=entry["action"],
            src=list(entry["src"]),
            dst=list(entry["dst"]),
        )
    except (KeyError, TypeError) as e:
        raise ValueError(f"acls[{index}] is invalid: {e}") from e
