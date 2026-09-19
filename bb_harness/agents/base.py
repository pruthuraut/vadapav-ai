"""
bb_harness.agents.base
BaseAgent abstraction — every recon agent inherits from this.
"""
from __future__ import annotations
import asyncio
from typing import Optional, Callable, List, Dict, Any
from datetime import datetime

from bb_harness.core.models import CheckItem, CheckStatus, AgentCategory
from bb_harness.core.db import Database
from bb_harness.core.runner import DualRunner, HostRunner
from bb_harness.core.config import scan_config, api_keys
from bb_harness.core.artifacts import ReconArtifacts


class BaseAgent:
    """
    Base class for recon agents.
    Each agent is responsible for a category of checks and contains
    methods named `_run_<check_id>` that implement individual checks.
    """

    AGENT_ID: str = ""
    CATEGORY: AgentCategory = AgentCategory.SUBDOMAIN_ENUM
    NAME: str = ""
    DESCRIPTION: str = ""

    def __init__(self, db: Database, runner: DualRunner, session_id: str):
        self.db = db
        self.runner = runner
        self.session_id = session_id
        self.config = scan_config
        self.keys = api_keys
        self.artifacts = ReconArtifacts(self.target, session_id, self.config.mode)
        self._active_check_id = "unattributed"
        self._tool_sequences: Dict[str, int] = {}
        self.enabled = True
        self._check_methods: Dict[str, Callable] = {}
        self._register_methods()

    def _register_methods(self):
        """Auto-discover methods named _run_<check_id>."""
        for name in dir(self):
            if name.startswith("_run_") and callable(getattr(self, name)):
                check_id = name[5:]  # strip _run_
                self._check_methods[check_id] = getattr(self, name)

    @property
    def target(self) -> str:
        return self.config.target

    @property
    def registered_checks(self) -> List[str]:
        return list(self._check_methods.keys())

    async def run_check(self, check: CheckItem, console=None) -> CheckItem:
        """Run a single check by its ID."""
        method = self._check_methods.get(check.check_id)
        if not method:
            check.status = CheckStatus.SKIPPED
            check.error_message = "No implementation"
            self.db.update_check(self.session_id, check.check_id,
                                 CheckStatus.SKIPPED, error_message="No implementation")
            return check

        # Mark running
        check.status = CheckStatus.RUNNING
        check.started_at = datetime.utcnow().isoformat()
        self.db.update_check(self.session_id, check.check_id, CheckStatus.RUNNING)

        if console:
            console.log_check_start(check)

        try:
            self._active_check_id = check.check_id
            result_count = await method()
            check.status = CheckStatus.DONE
            check.result_count = result_count or 0
            check.finished_at = datetime.utcnow().isoformat()
            self.db.update_check(
                self.session_id, check.check_id, CheckStatus.DONE,
                result_count=check.result_count,
            )
            if console:
                console.log_check_done(check)
        except Exception as e:
            check.status = CheckStatus.FAILED
            check.error_message = str(e)[:200]
            check.finished_at = datetime.utcnow().isoformat()
            self.db.update_check(
                self.session_id, check.check_id, CheckStatus.FAILED,
                error_message=check.error_message,
            )
            if console:
                console.log_check_fail(check)
        finally:
            self._active_check_id = "unattributed"

        return check

    async def run_all(self, checks: List[CheckItem], console=None,
                      concurrency: int = 5) -> List[CheckItem]:
        """Run all checks for this agent with concurrency limit."""
        sem = asyncio.Semaphore(concurrency)

        async def _run_with_sem(check):
            async with sem:
                return await self.run_check(check, console)

        results = await asyncio.gather(
            *[_run_with_sem(c) for c in checks],
            return_exceptions=True,
        )
        return [r for r in results if isinstance(r, CheckItem)]

    # ── Helper Utilities ──────────────────────────────────────────────────────

    async def run_tool(self, tool: str, cmd: str, timeout: int = 300):
        """Run an external tool through the dual runner."""
        result = await self.runner.run_tool(tool, cmd, timeout=timeout)
        stage_by_category = {
            AgentCategory.SUBDOMAIN_ENUM: "passive",
            AgentCategory.PORT_SCAN: "ports",
            AgentCategory.TECH_FINGERPRINT: "technology",
            AgentCategory.CONTENT_DISCOVERY: "web-surface",
            AgentCategory.LINK_PARAM_DISCOVERY: "js-analysis",
        }
        stage = stage_by_category.get(self.CATEGORY, "raw")
        key = f"{self._active_check_id}:{tool}"
        self._tool_sequences[key] = self._tool_sequences.get(key, 0) + 1
        self.artifacts.record_tool_output(
            stage=stage,
            check_id=self._active_check_id,
            tool=tool,
            stdout=result.stdout,
            stderr=result.stderr,
            mode=result.mode,
            returncode=result.returncode,
            sequence=self._tool_sequences[key],
        )
        return result

    async def http_get(self, url: str, timeout: int = 30) -> Optional[dict]:
        """Make an HTTP GET request and return {status, headers, text}."""
        import httpx
        try:
            async with httpx.AsyncClient(
                verify=False, follow_redirects=True, timeout=timeout,
                headers={"User-Agent": self.config.user_agent},
            ) as client:
                resp = await client.get(url)
                return {
                    "status": resp.status_code,
                    "headers": dict(resp.headers),
                    "text": resp.text,
                    "url": str(resp.url),
                }
        except Exception:
            return None

    async def http_get_json(self, url: str, timeout: int = 30,
                            headers: dict = None) -> Optional[Any]:
        """Make an HTTP GET request and return parsed JSON."""
        import httpx
        try:
            hdrs = {"User-Agent": self.config.user_agent}
            if headers:
                hdrs.update(headers)
            async with httpx.AsyncClient(
                verify=False, follow_redirects=True, timeout=timeout,
                headers=hdrs,
            ) as client:
                resp = await client.get(url)
                return resp.json()
        except Exception:
            return None

    async def resolve_dns(self, domain: str, rdtype: str = "A") -> List[str]:
        """Resolve a DNS record."""
        import dns.resolver
        try:
            answers = dns.resolver.resolve(domain, rdtype)
            return [str(r) for r in answers]
        except Exception:
            return []

    def is_tool_available(self, tool: str) -> bool:
        """Check if a CLI tool is available on PATH."""
        return HostRunner.is_available(tool)
