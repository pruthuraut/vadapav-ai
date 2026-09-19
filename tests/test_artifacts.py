import json

from bb_harness.core import artifacts
from bb_harness.core.artifacts import ReconArtifacts, safe_target
from bb_harness.core.db import Database


def test_safe_target_normalizes_wildcard_url():
    assert safe_target("*.Example.COM/path") == "example.com"


def test_export_snapshot_writes_domain_scoped_contract(tmp_path, monkeypatch):
    monkeypatch.setattr(artifacts, "OUTPUT_DIR", tmp_path)
    db = Database(":memory:")
    session_id = db.create_session("example.com", "host")
    recon = ReconArtifacts("example.com", session_id, "host")

    paths = recon.export_snapshot(db)

    assert (recon.root / "manifest.json").exists()
    assert (recon.root / "normalized" / "asset-graph.json").exists()
    assert (recon.root / "reports" / "recon.md").exists()
    report = json.loads((recon.root / "reports" / "recon.json").read_text())
    assert report["target"] == "example.com"
    assert paths["recon.md"].endswith("recon.md")
