import dataclasses
import json
import sys

from acl_converter.acl_parser import parse_acl
from acl_converter.firewall_spec import generate_rules


def process(acl_content: str, node_name: str) -> dict[str, str]:
    acl = parse_acl(acl_content)
    rules = generate_rules(acl, node_name)
    return {"rules": json.dumps([dataclasses.asdict(r) for r in rules])}


def main(stdin=None, stdout=None):
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout

    query = json.load(stdin)
    with open(query["acl_file"]) as f:
        acl_content = f.read()

    result = process(acl_content, query["node_name"])
    json.dump(result, stdout)


if __name__ == "__main__":
    main()
