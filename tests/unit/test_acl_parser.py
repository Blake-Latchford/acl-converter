import pytest
from acl_converter.acl_parser import parse_acl


def test_parse_minimal_acl():
    hujson = '{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}'
    acl = parse_acl(hujson)
    assert len(acl.acls) == 1
    assert acl.acls[0].action == "accept"
    assert acl.acls[0].src == ["*"]
    assert acl.acls[0].dst == ["*:*"]


def test_parse_comments():
    hujson = """
    {
        // This is a comment
        "acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
    }
    """
    acl = parse_acl(hujson)
    assert len(acl.acls) == 1


def test_parse_trailing_commas():
    hujson = """
    {
        "acls": [
            {
                "action": "accept",
                "src": ["*"],
                "dst": ["*:*"],
            },
        ]
    }
    """
    acl = parse_acl(hujson)
    assert len(acl.acls) == 1


def test_parse_empty_acls():
    hujson = '{"acls": []}'
    acl = parse_acl(hujson)
    assert acl.acls == []


def test_parse_empty_root():
    hujson = '{}'
    acl = parse_acl(hujson)
    assert acl.acls == []
    assert acl.groups == {}


def test_parse_hosts():
    hujson = '{"hosts": {"mydb": "10.20.0.5", "webserver": "10.20.0.10"}, "acls": []}'
    acl = parse_acl(hujson)
    assert acl.hosts == {"mydb": "10.20.0.5", "webserver": "10.20.0.10"}


def test_parse_hosts_with_cidr_notation():
    # Real ACL files use CIDR notation for hosts
    hujson = '{"hosts": {"postgresql.internal": "10.20.0.2/32", "webservers.internal": "10.20.10.1/29"}, "acls": []}'
    acl = parse_acl(hujson)
    assert acl.hosts == {"postgresql.internal": "10.20.0.2/32", "webservers.internal": "10.20.10.1/29"}


def test_parse_empty_hosts():
    hujson = '{}'
    acl = parse_acl(hujson)
    assert acl.hosts == {}


def test_parse_groups():
    hujson = '{"groups": {"group:servers": ["10.20.0.1", "10.20.0.2"]}, "acls": []}'
    acl = parse_acl(hujson)
    assert acl.groups == {"group:servers": ["10.20.0.1", "10.20.0.2"]}


def test_parse_proto_in_acl_entry():
    hujson = '{"acls": [{"action": "accept", "proto": "tcp", "src": ["*"], "dst": ["*:80"]}]}'
    acl = parse_acl(hujson)
    assert acl.acls[0].proto == "tcp"


def test_parse_missing_proto_defaults_to_empty():
    hujson = '{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:80"]}]}'
    acl = parse_acl(hujson)
    assert acl.acls[0].proto == ""


def test_parse_tag_owners():
    hujson = '{"tagOwners": {"tag:web": ["autogroup:admin"]}, "acls": []}'
    acl = parse_acl(hujson)
    assert acl.tag_owners == {"tag:web": ["autogroup:admin"]}


def test_parse_empty_tag_owners():
    hujson = '{}'
    acl = parse_acl(hujson)
    assert acl.tag_owners == {}
