import io
import json

import pytest

from acl_converter.main import main, process


def test_process_empty_acl():
    result = process("{}", "10.0.0.1")
    assert result == {"rules": "[]"}


def test_process_result_is_flat_string_map():
    result = process("{}", "10.0.0.1")
    assert all(isinstance(v, str) for v in result.values())


def test_process_matching_rule():
    hujson = '{"acls": [{"action": "accept", "src": ["10.0.0.2"], "dst": ["10.0.0.1:80"]}]}'
    rules = json.loads(process(hujson, "10.0.0.1")["rules"])
    assert rules == [{"type": "in", "action": "ACCEPT", "source": "10.0.0.2", "dest": "", "dport": "80", "proto": ""}]


def test_process_no_matching_rules():
    hujson = '{"acls": [{"action": "accept", "src": ["10.0.0.2"], "dst": ["10.0.0.3:80"]}]}'
    rules = json.loads(process(hujson, "10.0.0.1")["rules"])
    assert rules == []


def test_main_reads_file_and_writes_stdout(tmp_path):
    acl_file = tmp_path / "acls.hujson"
    acl_file.write_text(
        '{"acls": [{"action": "accept", "src": ["10.0.0.2"], "dst": ["10.0.0.1:80"]}]}'
    )

    stdin = io.StringIO(json.dumps({"acl_file": str(acl_file), "node_name": "10.0.0.1"}))
    stdout = io.StringIO()
    main(stdin=stdin, stdout=stdout)

    rules = json.loads(json.loads(stdout.getvalue())["rules"])
    assert len(rules) == 1
    assert rules[0]["source"] == "10.0.0.2"
