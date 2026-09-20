"""Post-recon attack-phase coordinator.

Coordinates checklist coverage after recon while preserving scope, evidence,
rate-limit, and approval controls. It delegates safe execution to the existing
ReconSecurityAgent and does not invent credentials or exploit payloads.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from bb_harness.agents.security_testing import ReconSecurityAgent, TrafficRecord


class AttackPhaseAgent:
    """Start the testing phase for a completed bb-harness recon session."""

    AGENT_ID = "attack_phase"
    NAME = "Post-Recon Attack Phase"

    def __init__(self, db, runner, session_id: str, checklist_path: str | Path, traffic: Iterable[TrafficRecord] = ()):
        self.db = db
        self.runner = runner
        self.session_id = session_id
        self.checklist_path = Path(checklist_path)
        self.traffic = list(traffic)
        self.security = ReconSecurityAgent(db, runner, session_id, self.checklist_path, self.traffic)

    def verify_recon_context(self) -> dict[str, Any]:
        summary = self.db.get_summary(self.session_id)
        row = self.db.conn.execute("SELECT target FROM sessions WHERE session_id = ?", (self.session_id,)).fetchone()
        target = row["target"] if row else ""
        if not self.checklist_path.exists():
            raise FileNotFoundError(f"Checklist not found: {self.checklist_path}")
        if not summary:
            raise ValueError("Recon session was not found")
        return {
            "session_id": self.session_id,
            "target": target,
            "recon_assets": {
                "subdomains": summary.get("subdomains", 0),
                "endpoints": summary.get("endpoints", 0),
                "parameters": summary.get("parameters", 0),
                "technologies": summary.get("technologies", 0),
            },
        }

    async def start(self) -> dict[str, Any]:
        """Run the complete post-recon checklist workflow."""
        context = self.verify_recon_context()
        report = await self.security.run_all_items()
        report["context"] = context
        report["execution_policy"] = {
            "safe_checks": "automatic",
            "manual_checks": "approval_required",
            "high_impact_checks": "blocked_until_isolated_adapter_and_approval",
            "execution_mode": "host",
        }
        return report
