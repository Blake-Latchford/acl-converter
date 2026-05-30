import pytest
from plugins.module_utils.acl_parser import parse_acl


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