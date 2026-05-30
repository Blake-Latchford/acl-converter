from dataclasses import dataclass, field

import hjson


@dataclass
class AclEntry:
    action: str
    src: list[str]
    dst: list[str]


@dataclass
class Acl:
    acls: list[AclEntry] = field(default_factory=list)


def parse_acl(hujson: str) -> Acl:
    data = hjson.loads(hujson)
    if not isinstance(data, dict):
        raise ValueError("ACL must be a JSON object")

    return Acl(acls=[_parse_entry(i, e) for i, e in enumerate(data.get("acls", []))])


def _parse_entry(index: int, entry) -> AclEntry:
    try:
        return AclEntry(
            action=entry["action"],
            src=list(entry["src"]),
            dst=list(entry["dst"]),
        )
    except (KeyError, TypeError) as e:
        raise ValueError(f"acls[{index}] is invalid: {e}") from e
