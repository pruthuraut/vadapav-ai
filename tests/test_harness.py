"""
Unit and integration tests for bb-harness.
"""
import pytest
import asyncio
from bb_harness.core.checklist import build_checklist, TOTAL_CHECKS
from bb_harness.core.db import Database
from bb_harness.core.runner import DualRunner
from bb_harness.core.config import scan_config
from bb_harness.agents.subdomain_enum import SubdomainEnumAgent
from bb_harness.agents.port_scan import PortScanAgent
from bb_harness.agents.tech_fingerprint import TechFingerprintAgent
from bb_harness.agents.content_discovery import ContentDiscoveryAgent
from bb_harness.agents.link_param_discovery import LinkParamDiscoveryAgent
from bb_harness.cli.console import ScanConsole

def test_checklist_total():
    checklist = build_checklist()
    assert len(checklist) == TOTAL_CHECKS == 230

def test_db_session_and_checks():
    db = Database(":memory:")
    session_id = db.create_session("test.local", "host")
    assert session_id is not None
    checklist = build_checklist()
    db.init_checks(session_id, checklist)
    checks = db.get_checks(session_id)
    assert len(checks) == 230
    summary = db.get_summary(session_id)
    assert summary["checks_total"] == 230
    assert summary["checks_done"] == 0

@pytest.mark.asyncio
async def test_subdomain_agent_runs_checks():
    db = Database(":memory:")
    session_id = db.create_session("example.com", "host")
    runner = DualRunner(mode="host")
    agent = SubdomainEnumAgent(db, runner, session_id)
    checklist = build_checklist()
    db.init_checks(session_id, checklist)
    sub_checks = [c for c in checklist if c.category.value == "subdomain_enum"][:3]
    console = ScanConsole()
    await agent.run_all(sub_checks, console, concurrency=1)
    summary = db.get_summary(session_id)
    assert summary["checks_done"] >= 1

@pytest.mark.asyncio
async def test_all_agents_instantiate_and_run_sample_check():
    db = Database(":memory:")
    session_id = db.create_session("example.com", "host")
    runner = DualRunner(mode="host")
    checklist = build_checklist()
    db.init_checks(session_id, checklist)
    console = ScanConsole()

    agents = [
        (PortScanAgent(db, runner, session_id), "port_scan"),
        (TechFingerprintAgent(db, runner, session_id), "tech_fingerprint"),
        (ContentDiscoveryAgent(db, runner, session_id), "content_discovery"),
        (LinkParamDiscoveryAgent(db, runner, session_id), "link_param_discovery"),
    ]

    for agent, cat in agents:
        checks = [c for c in checklist if c.category.value == cat][:2]
        await agent.run_all(checks, console, concurrency=1)

    summary = db.get_summary(session_id)
    assert summary["checks_done"] >= 4

