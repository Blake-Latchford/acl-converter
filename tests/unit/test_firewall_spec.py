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


def test_host_alias_in_dst_matches_node_ip():
    acl = Acl(
        hosts={"mydb": "10.20.0.5"},
        acls=[AclEntry(action="accept", src=["10.0.0.2"], dst=["mydb:5432"])],
    )
    rules = generate_rules(acl, "10.20.0.5")
    assert rules == [FirewallRule(type="in", action="ACCEPT", source="10.0.0.2", dport="5432")]


def test_host_alias_in_src_resolves_to_ip():
    acl = Acl(
        hosts={"webserver": "10.20.0.10"},
        acls=[AclEntry(action="accept", src=["webserver"], dst=["10.20.0.5:5432"])],
    )
    rules = generate_rules(acl, "10.20.0.5")
    assert rules == [FirewallRule(type="in", action="ACCEPT", source="10.20.0.10", dport="5432")]


def test_host_alias_in_dst_does_not_match_different_ip():
    acl = Acl(
        hosts={"mydb": "10.20.0.5"},
        acls=[AclEntry(action="accept", src=["10.0.0.2"], dst=["mydb:5432"])],
    )
    rules = generate_rules(acl, "10.20.0.99")
    assert rules == []


def test_group_in_dst_matches_member_node():
    acl = Acl(
        groups={"group:servers": ["10.20.0.1", "10.20.0.2"]},
        acls=[AclEntry(action="accept", src=["10.0.0.1"], dst=["group:servers:22"])],
    )
    rules = generate_rules(acl, "10.20.0.1")
    assert rules == [FirewallRule(type="in", action="ACCEPT", source="10.0.0.1", dport="22")]


def test_group_in_dst_does_not_match_non_member():
    acl = Acl(
        groups={"group:servers": ["10.20.0.1", "10.20.0.2"]},
        acls=[AclEntry(action="accept", src=["10.0.0.1"], dst=["group:servers:22"])],
    )
    rules = generate_rules(acl, "10.20.0.99")
    assert rules == []


def test_group_in_src_generates_one_rule_per_member():
    acl = Acl(
        groups={"group:admins": ["10.0.0.1", "10.0.0.2"]},
        acls=[AclEntry(action="accept", src=["group:admins"], dst=["10.20.0.1:22"])],
    )
    rules = generate_rules(acl, "10.20.0.1")
    assert rules == [
        FirewallRule(type="in", action="ACCEPT", source="10.0.0.1", dport="22"),
        FirewallRule(type="in", action="ACCEPT", source="10.0.0.2", dport="22"),
    ]


def test_cidr_dst_matches_node_in_range():
    acl = Acl(acls=[AclEntry(action="accept", src=["10.0.0.1"], dst=["10.20.0.0/24:80"])])
    rules = generate_rules(acl, "10.20.0.5")
    assert rules == [FirewallRule(type="in", action="ACCEPT", source="10.0.0.1", dport="80")]


def test_cidr_dst_does_not_match_node_outside_range():
    acl = Acl(acls=[AclEntry(action="accept", src=["10.0.0.1"], dst=["10.20.0.0/24:80"])])
    rules = generate_rules(acl, "10.30.0.5")
    assert rules == []


def test_cidr_src_passes_through_as_source():
    acl = Acl(acls=[AclEntry(action="accept", src=["10.0.0.0/8"], dst=["10.20.0.5:443"])])
    rules = generate_rules(acl, "10.20.0.5")
    assert rules == [FirewallRule(type="in", action="ACCEPT", source="10.0.0.0/8", dport="443")]
