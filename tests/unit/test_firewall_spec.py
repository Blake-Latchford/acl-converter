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
    assert FirewallRule(type="in", action="ACCEPT", source="", dport="443") in rules


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
    assert FirewallRule(type="in", action="ACCEPT", source="10.0.0.0/8", dport="443") in rules


def test_proto_passed_through_to_inbound_rule():
    acl = Acl(acls=[AclEntry(action="accept", proto="tcp", src=["10.0.0.1"], dst=["10.0.0.2:80"])])
    rules = generate_rules(acl, "10.0.0.2")
    assert rules == [FirewallRule(type="in", action="ACCEPT", source="10.0.0.1", dport="80", proto="tcp")]


def test_missing_proto_defaults_to_empty_in_rule():
    acl = Acl(acls=[AclEntry(action="accept", src=["10.0.0.1"], dst=["10.0.0.2:80"])])
    rules = generate_rules(acl, "10.0.0.2")
    assert rules[0].proto == ""


def test_node_as_src_generates_outbound_rule():
    acl = Acl(acls=[AclEntry(action="accept", src=["10.0.0.1"], dst=["10.0.0.2:80"])])
    rules = generate_rules(acl, "10.0.0.1")
    assert FirewallRule(type="out", action="ACCEPT", dest="10.0.0.2", dport="80") in rules


def test_wildcard_src_generates_outbound_rule():
    acl = Acl(acls=[AclEntry(action="accept", src=["*"], dst=["10.0.0.2:80"])])
    rules = generate_rules(acl, "10.0.0.1")
    assert FirewallRule(type="out", action="ACCEPT", dest="10.0.0.2", dport="80") in rules


def test_group_src_generates_outbound_for_member():
    acl = Acl(
        groups={"group:clients": ["10.0.0.1", "10.0.0.2"]},
        acls=[AclEntry(action="accept", src=["group:clients"], dst=["10.20.0.5:443"])],
    )
    rules = generate_rules(acl, "10.0.0.1")
    assert FirewallRule(type="out", action="ACCEPT", dest="10.20.0.5", dport="443") in rules


def test_proto_passed_through_to_outbound_rule():
    acl = Acl(acls=[AclEntry(action="accept", proto="udp", src=["10.0.0.1"], dst=["10.0.0.2:53"])])
    rules = generate_rules(acl, "10.0.0.1")
    assert FirewallRule(type="out", action="ACCEPT", dest="10.0.0.2", dport="53", proto="udp") in rules


# --- hosts with CIDR notation ---

def test_host_with_slash32_matches_exact_ip():
    # Real ACL files use /32 for single-host aliases
    acl = Acl(
        hosts={"postgresql.internal": "10.20.0.2/32"},
        acls=[AclEntry(action="accept", src=["10.0.0.1"], dst=["postgresql.internal:5432"])],
    )
    rules = generate_rules(acl, "10.20.0.2")
    assert FirewallRule(type="in", action="ACCEPT", source="10.0.0.1", dport="5432") in rules


def test_host_with_slash32_does_not_match_different_ip():
    acl = Acl(
        hosts={"postgresql.internal": "10.20.0.2/32"},
        acls=[AclEntry(action="accept", src=["10.0.0.1"], dst=["postgresql.internal:5432"])],
    )
    rules = generate_rules(acl, "10.20.0.3")
    assert rules == []


def test_host_with_subnet_cidr_matches_node_in_range():
    # e.g. "webservers.internal": "10.20.10.1/29" covers 10.20.10.0–10.20.10.7
    acl = Acl(
        hosts={"webservers.internal": "10.20.10.1/29"},
        acls=[AclEntry(action="accept", src=["10.0.0.1"], dst=["webservers.internal:80"])],
    )
    rules = generate_rules(acl, "10.20.10.4")
    assert FirewallRule(type="in", action="ACCEPT", source="10.0.0.1", dport="80") in rules


def test_host_with_subnet_cidr_does_not_match_node_outside_range():
    acl = Acl(
        hosts={"webservers.internal": "10.20.10.1/29"},
        acls=[AclEntry(action="accept", src=["10.0.0.1"], dst=["webservers.internal:80"])],
    )
    rules = generate_rules(acl, "10.20.10.9")
    assert rules == []


# --- port syntax ---

def test_comma_separated_ports_passed_through_as_dport():
    acl = Acl(acls=[AclEntry(action="accept", src=["10.0.0.1"], dst=["10.0.0.2:80,443"])])
    rules = generate_rules(acl, "10.0.0.2")
    assert FirewallRule(type="in", action="ACCEPT", source="10.0.0.1", dport="80,443") in rules


def test_port_range_passed_through_as_dport():
    acl = Acl(acls=[AclEntry(action="accept", src=["10.0.0.1"], dst=["10.0.0.2:8000-9000"])])
    rules = generate_rules(acl, "10.0.0.2")
    assert FirewallRule(type="in", action="ACCEPT", source="10.0.0.1", dport="8000-9000") in rules


# --- opaque identifiers ---

def test_tag_in_src_passes_through_as_source():
    acl = Acl(acls=[AclEntry(action="accept", src=["tag:app"], dst=["10.0.0.1:443"])])
    rules = generate_rules(acl, "10.0.0.1")
    assert FirewallRule(type="in", action="ACCEPT", source="tag:app", dport="443") in rules


def test_autogroup_in_src_does_not_crash():
    # autogroup:* identifiers can't be resolved without the API; no rules generated
    acl = Acl(acls=[AclEntry(action="accept", src=["autogroup:member"], dst=["10.0.0.1:80"])])
    rules = generate_rules(acl, "10.0.0.1")
    assert FirewallRule(type="in", action="ACCEPT", source="autogroup:member", dport="80") in rules


def test_group_with_email_members_passes_through_as_source():
    # Groups may contain user emails (e.g. "dev1@") rather than IPs
    acl = Acl(
        groups={"group:dev": ["dev1@example.com", "dev2@example.com"]},
        acls=[AclEntry(action="accept", src=["group:dev"], dst=["10.0.0.1:22"])],
    )
    rules = generate_rules(acl, "10.0.0.1")
    sources = {r.source for r in rules if r.type == "in"}
    assert sources == {"dev1@example.com", "dev2@example.com"}


def test_group_with_email_members_does_not_match_as_dst_node():
    # A node identified by IP should not match a group whose members are emails
    acl = Acl(
        groups={"group:dev": ["dev1@example.com"]},
        acls=[AclEntry(action="accept", src=["10.0.0.1"], dst=["group:dev:22"])],
    )
    rules = generate_rules(acl, "10.0.0.2")
    assert rules == []
