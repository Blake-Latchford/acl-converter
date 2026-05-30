"""
Terraform external data source entry point.

Reads a JSON query from stdin:
  {
    "acl_file": "/path/to/acls.hujson",
    "node_name": "my-vm"
  }

Writes a flat JSON map to stdout:
  {
    "rules": "<JSON-encoded list of firewall rule objects>"
  }
"""
import json
import sys

from acl_converter.acl_parser import parse_acl


def main():
    query = json.load(sys.stdin)
    acl_file = query["acl_file"]
    node_name = query["node_name"]

    with open(acl_file) as f:
        acl = parse_acl(f.read())

    raise NotImplementedError


if __name__ == "__main__":
    main()
