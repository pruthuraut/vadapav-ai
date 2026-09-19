import json

from bb_harness.core import artifacts
from bb_harness.core.artifacts import ReconArtifacts, safe_target
from bb_harness.core.db import Database
from bb_harness.core.models import Endpoint


def test_safe_target_normalizes_wildcard_url():
    assert safe_target("*.Example.COM/path") == "example.com"


def test_export_snapshot_writes_domain_scoped_contract(tmp_path, monkeypatch):
    monkeypatch.setattr(artifacts, "OUTPUT_DIR", tmp_path)
    db = Database(":memory:")
    session_id = db.create_session("example.com", "host")
    db.add_endpoint(session_id, Endpoint("https://example.com/api/users?id=7"))
    db.add_endpoint(session_id, Endpoint("https://example.com/login"))
    db.add_endpoint(session_id, Endpoint("https://example.com/assets/app.js?v=1"))
    recon = ReconArtifacts("example.com", session_id, "host")

    paths = recon.export_snapshot(db)

    assert (recon.root / "manifest.json").exists()
    assert (recon.root / "subdomains.txt").exists()
    assert (recon.root / "urls.txt").exists()
    assert "assets/app.js" in (recon.root / "javascript.txt").read_text()
    assert "api/users" in (recon.root / "api-endpoints.txt").read_text()
    assert "login" in (recon.root / "auth-paths.txt").read_text()
    assert "users?id=7" in (recon.root / "interesting-params.txt").read_text()
    assert (recon.root / "normalized" / "urls.txt").exists()
    assert (recon.root / "normalized" / "asset-graph.json").exists()
    assert (recon.root / "reports" / "recon.md").exists()
    report = json.loads((recon.root / "reports" / "recon.json").read_text())
    assert report["target"] == "example.com"
    assert paths["recon.md"].endswith("recon.md")


def test_record_tool_output_preserves_raw_stdout_and_stderr(tmp_path, monkeypatch):
    monkeypatch.setattr(artifacts, "OUTPUT_DIR", tmp_path)
    recon = ReconArtifacts("example.com", "raw-test", "container")
    path = recon.record_tool_output(
        "passive", "sub_001", "subfinder", "a.example.com\n", "warning\n", "container", 0
    )

    text = path.read_text()
    assert path.name == "sub_001_subfinder_1.txt"
    assert "a.example.com" in text
    assert "warning" in text
