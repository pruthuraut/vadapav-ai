"""Recon artifact layout and export helpers.

Every recon session gets an isolated, reproducible directory under
``output/recon/<domain>/<session_id>/``.  The database remains the source of
truth; these files are portable snapshots for operators and downstream skills.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from bb_harness.core.config import OUTPUT_DIR


def safe_target(value: str) -> str:
    """Return a filesystem-safe, normalized target label."""
    value = (value or "unknown").strip().lower().lstrip("*.")
    value = re.sub(r"^https?://", "", value).split("/", 1)[0].split(":", 1)[0]
    value = re.sub(r"[^a-z0-9._-]+", "_", value).strip("._-")
    return value or "unknown"


class ReconArtifacts:
    """Create and export the portable artifact tree for one recon session."""

    STAGES = (
        "passive",
        "dns",
        "live-hosts",
        "ports",
        "technology",
        "web-surface",
        "js-analysis",
        "triage",
    )

    def __init__(self, target: str, session_id: str, mode: str = "host"):
        self.target = target
        self.session_id = session_id
        self.mode = mode
        self.domain = safe_target(target)
        self.root = OUTPUT_DIR / "recon" / self.domain / session_id
        self.raw = self.root / "raw"
        self.normalized = self.root / "normalized"
        self.reports = self.root / "reports"
        self.logs = self.root / "logs"
        for path in (self.raw, self.normalized, self.reports, self.logs):
            path.mkdir(parents=True, exist_ok=True)
        for stage in self.STAGES:
            (self.raw / stage).mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.root / "manifest.json"

    @property
    def relative_root(self) -> str:
        return str(Path("output") / "recon" / self.domain / self.session_id)

    def manifest(self, status: str = "running") -> dict[str, Any]:
        return {
            "schema_version": 1,
            "target": self.target,
            "domain": self.domain,
            "session_id": self.session_id,
            "mode": self.mode,
            "status": status,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "layout": {
                "raw": "raw/<stage>/",
                "normalized": "normalized/",
                "reports": "reports/",
                "logs": "logs/",
            },
            "stages": list(self.STAGES),
        }

    def write_manifest(self, status: str = "running") -> Path:
        self.manifest_path.write_text(
            json.dumps(self.manifest(status), indent=2) + "\n", encoding="utf-8"
        )
        return self.manifest_path

    def write_json(self, relative: str, value: Any) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2, default=str) + "\n", encoding="utf-8")
        return path

    def export_snapshot(self, db, status: str = "completed") -> dict[str, str]:
        """Export normalized inventories and a human-readable recon report."""
        summary = db.get_summary(self.session_id)
        inventories = {
            "subdomains.json": db.get_subdomains(self.session_id),
            "live-hosts.json": [
                row for row in db.get_subdomains(self.session_id) if row.get("is_alive")
            ],
            "open-ports.json": db.get_ports(self.session_id),
            "technologies.json": db.get_technologies(self.session_id),
            "endpoints.json": db.get_endpoints(self.session_id),
            "parameters.json": db.get_parameters(self.session_id),
            "findings.json": db.get_findings(self.session_id),
            "checks.json": db.get_checks(self.session_id),
        }
        paths: dict[str, str] = {}
        for name, value in inventories.items():
            paths[name] = str(self.write_json(f"normalized/{name}", value))

        graph = {
            "target": self.target,
            "session_id": self.session_id,
            "nodes": {
                "subdomains": inventories["subdomains.json"],
                "ports": inventories["open-ports.json"],
                "technologies": inventories["technologies.json"],
                "endpoints": inventories["endpoints.json"],
                "parameters": inventories["parameters.json"],
            },
            "summary": summary,
        }
        paths["asset-graph.json"] = str(self.write_json("normalized/asset-graph.json", graph))

        report = {
            "target": self.target,
            "domain": self.domain,
            "session_id": self.session_id,
            "mode": self.mode,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "inventories": inventories,
            "artifact_root": self.relative_root,
        }
        paths["recon.json"] = str(self.write_json("reports/recon.json", report))

        lines = [
            f"# Recon Report: {self.target}",
            "",
            f"- Session: `{self.session_id}`",
            f"- Mode: `{self.mode}`",
            f"- Artifact root: `{self.relative_root}`",
            "",
            "## Summary",
            "",
            "| Metric | Count |",
            "|---|---:|",
        ]
        lines.extend(f"| {key.replace('_', ' ').title()} | {value} |" for key, value in summary.items())
        lines.extend([
            "",
            "## Inventory files",
            "",
            *[f"- `normalized/{name}`" for name in inventories],
            "- `normalized/asset-graph.json`",
            "",
            "Automated observations are preliminary and require review before being treated as confirmed findings.",
        ])
        md_path = self.reports / "recon.md"
        md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        paths["recon.md"] = str(md_path)
        self.write_manifest(status)
        return paths
