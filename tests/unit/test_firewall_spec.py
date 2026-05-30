import pytest
from acl_converter.acl_parser import Acl, AclEntry
from acl_converter.firewall_spec import FirewallRule, generate_rules


def test_empty_acl_generates_no_rules():
    rules = generate_rules(Acl(), "10.0.0.1")
    assert rules == []


def test_node_as_dst_generates_inbound_rule():
    acl = Acl(acls=[AclEntry(action="accept", src=["10.0.0.2"], dst=["10.0.0.1:80"])])
    rules = generate_rules(acl, "10.0.0.1")
    assert rules == [FirewallRule(type="in", action="ACCEPT", source="10.0.0.2", dport="80")]


def test_node_not_in_dst_generates_no_rules():
    acl = Acl(acls=[AclEntry(action="accept", src=["10.0.0.2"], dst=["10.0.0.3:80"])])
    rules = generate_rules(acl, "10.0.0.1")
    assert rules == []


def test_wildcard_dst_matches_any_node():
    acl = Acl(acls=[AclEntry(action="accept", src=["10.0.0.2"], dst=["*:80"])])
    rules = generate_rules(acl, "10.0.0.1")
    assert rules == [FirewallRule(type="in", action="ACCEPT", source="10.0.0.2", dport="80")]


def test_wildcard_src_produces_empty_source():
    acl = Acl(acls=[AclEntry(action="accept", src=["*"], dst=["10.0.0.1:443"])])
    rules = generate_rules(acl, "10.0.0.1")
    assert rules == [FirewallRule(type="in", action="ACCEPT", source="", dport="443")]


def test_wildcard_port_produces_empty_dport():
    acl = Acl(acls=[AclEntry(action="accept", src=["10.0.0.2"], dst=["10.0.0.1:*"])])
    rules = generate_rules(acl, "10.0.0.1")
    assert rules == [FirewallRule(type="in", action="ACCEPT", source="10.0.0.2", dport="")]


def test_multiple_src_generates_one_rule_per_src():
    acl = Acl(acls=[
        AclEntry(action="accept", src=["10.0.0.2", "10.0.0.3"], dst=["10.0.0.1:80"])
    ])
    rules = generate_rules(acl, "10.0.0.1")
    assert rules == [
        FirewallRule(type="in", action="ACCEPT", source="10.0.0.2", dport="80"),
        FirewallRule(type="in", action="ACCEPT", source="10.0.0.3", dport="80"),
    ]


def test_multiple_dst_specs_only_matches_node():
    acl = Acl(acls=[
        AclEntry(action="accept", src=["10.0.0.2"], dst=["10.0.0.1:80", "10.0.0.3:80"])
    ])
    rules = generate_rules(acl, "10.0.0.1")
    assert rules == [FirewallRule(type="in", action="ACCEPT", source="10.0.0.2", dport="80")]


def test_tag_dst_parsed_correctly():
    acl = Acl(acls=[AclEntry(action="accept", src=["10.0.0.2"], dst=["tag:web:443"])])
    rules = generate_rules(acl, "tag:web")
    assert rules == [FirewallRule(type="in", action="ACCEPT", source="10.0.0.2", dport="443")]
