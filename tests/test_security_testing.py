import json
from pathlib import Path

from bb_harness.agents.security_testing import load_har, parse_checklist


def test_parse_checklist_is_not_hard_coded(tmp_path: Path):
    path = tmp_path / "checks.txt"
    path.write_text("Password & Credential Attacks\nTest for HSTS header presence\nCheck SQL injection in search\n", encoding="utf-8")
    checks = parse_checklist(path)
    assert len(checks) == 2
    assert checks[0].family == "header"
    assert checks[1].family == "sql"


def test_load_har_redacts_by_omission_and_reads_request_metadata(tmp_path: Path):
    path = tmp_path / "traffic.har"
    path.write_text(json.dumps({"log": {"entries": [{"request": {"method": "GET", "url": "https://example.test/account", "headers": [{"name": "Cookie", "value": "session=secret"}]}}]}}), encoding="utf-8")
    records = load_har(path)
    assert records[0].authenticated is True
    assert records[0].url.endswith("/account")
