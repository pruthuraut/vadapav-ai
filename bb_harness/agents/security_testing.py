"""Recon-driven, authorization-gated web security assessment.

This module deliberately favors safe verification and planning over exploit
automation. It consumes the existing recon database and can ingest HAR/Burp
exports without storing credentials or replaying arbitrary traffic by default.
"""
from __future__ import annotations

import json
import re
import secrets
import ssl
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional
from urllib.parse import urlparse

from bb_harness.agents.base import BaseAgent
from bb_harness.core.models import Finding, Severity
from bb_harness.agents.tool_router import ToolRouter


@dataclass
class SecurityCheck:
    check_id: str
    description: str
    family: str = "other"
    assets: list[str] = field(default_factory=list)
    mode: str = "manual"  # automated, manual, blocked, not_applicable
    reason: str = ""


@dataclass
class TrafficRecord:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    authenticated: bool = False
    source: str = "har"


@dataclass
class TestPlan:
    """A reproducible plan and proof standard for one checklist item."""
    check_id: str
    checklist_text: str
    family: str
    targets: list[str]
    preconditions: list[str]
    steps: list[str]
    proof_requirements: list[str]
    execution_mode: str


CHECK_RE = re.compile(
    r"^(?P<text>(?:Test|Check|Verify|Analyze|Google dork):?\s+.+?)\s*$",
    re.IGNORECASE,
)
FAMILIES = (
    "password", "credential", "session", "oauth", "sso", "login", "authentication",
    "idor", "privilege", "path traversal", "file", "sql", "xss", "ssrf", "template",
    "command", "nosql", "ldap", "xml", "xxe", "csrf", "cors", "clickjacking",
    "postmessage", "tls", "cryptographic", "jwt", "websocket", "graphql", "header",
    "cookie", "csp", "cloud", "dns", "subdomain", "rate limit", "open redirect",
    "deserialization", "business logic", "race condition", "prototype pollution",
)
BLOCKED_TERMS = re.compile(
    r"brute.?force|credential stuffing|password spray|dos|denial.of.service|rce|remote code execution|"
    r"exfil|metadata endpoint|internal service|out.of.band|dns interaction|captcha solving|social engineering|"
    r"sim swapping|ntlm relay|kerberos delegation|cloud credential|read_file|cmd_shell",
    re.IGNORECASE,
)
AUTOMATED_PHRASES = re.compile(
    r"header|cookie|hsts|tls version|certificate|content.security.policy|x-frame|cors|same.?site|"
    r"referrer.policy|security header|server header|robots.txt|sitemap|directory listing|open redirect",
    re.IGNORECASE,
)


def parse_checklist(path: str | Path) -> list[SecurityCheck]:
    """Parse the user's large plain-text checklist without hard-coded counts."""
    checks: list[SecurityCheck] = []
    for n, line in enumerate(Path(path).read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        match = CHECK_RE.match(line.strip())
        if not match:
            continue
        description = match.group("text").strip()
        low = description.lower()
        family = next((f for f in FAMILIES if f in low), "other")
        mode = "blocked" if BLOCKED_TERMS.search(description) else ("automated" if AUTOMATED_PHRASES.search(description) else "manual")
        checks.append(SecurityCheck(f"sec_{n:05d}", description, family, mode=mode))
    return checks


def load_har(path: str | Path) -> list[TrafficRecord]:
    """Load request metadata from a HAR export; response bodies are ignored."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out = []
    for entry in data.get("log", {}).get("entries", []):
        req = entry.get("request", {})
        headers = {str(h.get("name", "")): str(h.get("value", "")) for h in req.get("headers", [])}
        body = str(req.get("postData", {}).get("text", ""))
        out.append(TrafficRecord(str(req.get("method", "GET")), str(req.get("url", "")), headers, body, authenticated=bool(headers.get("Authorization") or headers.get("Cookie"))))
    return out


class ReconSecurityAgent(BaseAgent):
    """Correlates recon assets to safe security checks and records evidence."""

    AGENT_ID = "security_testing"
    NAME = "Recon-driven Security Testing"
    DESCRIPTION = "Maps the complete security checklist to recon assets and runs safe checks."

    def __init__(self, db, runner, session_id, checklist_path: str | Path | None = None, traffic: Iterable[TrafficRecord] = ()):
        super().__init__(db, runner, session_id)
        row = db.conn.execute("SELECT target FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
        self.scope_target = (row["target"] if row else self.config.target).lower().strip().rstrip(".")
        self.security_checks = parse_checklist(checklist_path) if checklist_path else []
        self.traffic = list(traffic)
        self.request_budget = 250
        self._requests = 0
        manifest = Path("tools/tool-manifest.json")
        self.tool_router = ToolRouter(manifest) if manifest.exists() else None

    def _in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower().strip().rstrip(".")
        return parsed.scheme in {"http", "https"} and bool(host) and (host == self.scope_target or host.endswith("." + self.scope_target))

    def build_asset_graph(self) -> dict[str, list[dict[str, Any]]]:
        assets: dict[str, list[dict[str, Any]]] = {}
        for row in self.db.get_endpoints(self.session_id):
            assets.setdefault("endpoints", []).append(row)
        for row in self.db.get_parameters(self.session_id):
            assets.setdefault("parameters", []).append(row)
        for row in self.db.get_subdomains(self.session_id):
            assets.setdefault("subdomains", []).append(row)
        for row in self.db.get_technologies(self.session_id):
            assets.setdefault("technologies", []).append(row)
        for record in self.traffic:
            assets.setdefault("authenticated_traffic", []).append({"method": record.method, "url": record.url, "source": record.source})
        return assets

    def map_checks(self) -> list[SecurityCheck]:
        assets = self.build_asset_graph()
        urls = [str(x.get("url", "")) for x in assets.get("endpoints", [])] + [str(x.get("url", "")) for x in assets.get("authenticated_traffic", [])]
        urls = [u for u in urls if self._in_scope(u)]
        params = [str(x.get("name", "")) for x in assets.get("parameters", [])]
        tech = " ".join(str(x.get("name", "")) for x in assets.get("technologies", [])).lower()
        for check in self.security_checks:
            terms = set(re.findall(r"[a-z0-9_/-]{3,}", check.description.lower()))
            check.assets = [u for u in urls if any(t in u.lower() for t in terms)][:20]
            if not check.assets and (check.family in {"sql", "xss", "ssrf", "command", "path traversal", "idor", "csrf", "cors", "open redirect"}):
                check.assets = urls[:20] if urls else []
            if not check.assets and check.family in {"password", "login", "authentication", "session", "oauth", "sso", "jwt", "cookie"}:
                check.assets = [u for u in urls if any(k in u.lower() for k in ("login", "auth", "session", "oauth", "sso", "account", "password", "token"))][:20]
            if not check.assets and any(p in terms for p in params):
                check.assets = urls[:20]
            if not check.assets and check.family not in {"tls", "header", "security header", "dns", "subdomain", "cloud"} and not tech:
                check.mode = "not_applicable"
                check.reason = "No matching recon asset, parameter, traffic, or technology"
        return self.security_checks

    def build_test_plans(self) -> list[TestPlan]:
        """Create an auditable plan for every parsed check without changing its text."""
        self.map_checks()
        plans = []
        for check in self.security_checks:
            target_text = ", ".join(check.assets[:10]) or "the matching recon asset(s)"
            preconditions = [
                "Target is in the approved allowlist",
                "Record baseline response, status, headers, and timing",
                "Use only supplied test identities and authenticated traffic",
            ]
            steps = [
                f"Select the applicable asset(s): {target_text}.",
                "Capture a baseline request/response without modification.",
                f"Apply the checklist-specific test: {check.description}.",
                "Compare the result with the baseline and repeat once to confirm reproducibility.",
            ]
            proof = [
                "Exact target, method, timestamp, and sanitized request/response pair",
                "Observed security-relevant difference and why it demonstrates the issue",
                "Reproduction count and confidence level",
                "No claim based solely on a banner, error string, or missing header",
            ]
            if check.mode in {"blocked", "manual"}:
                steps.append("Pause for human approval before sending any high-impact or state-changing request.")
                proof.append("Approval record and cleanup/rollback confirmation where applicable")
            plans.append(TestPlan(check.check_id, check.description, check.family, check.assets, preconditions, steps, proof, check.mode))
        return plans

    async def run_safe_header_check(self, url: str, check: SecurityCheck) -> int:
        if not self._in_scope(url):
            check.reason = "Target is outside the authorized session scope"
            return 0
        if self._requests >= self.request_budget:
            check.mode, check.reason = "manual", "Request budget exhausted"
            return 0
        self._requests += 1
        response = await self.http_get(url, timeout=min(self.config.timeout, 15))
        if not response:
            check.reason = "Request failed"
            return 0
        headers = {k.lower(): v for k, v in response["headers"].items()}
        missing = [h for h in ("strict-transport-security", "content-security-policy", "x-content-type-options", "referrer-policy") if h not in headers]
        if missing:
            self.db.add_finding(self.session_id, Finding(f"Missing security headers: {', '.join(missing)}", Severity.LOW, url, "One or more recommended response headers were absent.", json.dumps({"missing": missing, "status": response["status"]}), "security_testing", check.check_id))
            return len(missing)
        return 0

    async def assess(self) -> dict[str, int]:
        """Map and process every checklist item; safely automate only low-impact checks."""
        self.map_checks()
        counts = {k: 0 for k in ("automated", "manual", "blocked", "not_applicable", "findings")}
        urls = list(dict.fromkeys([x.url for x in self.traffic] + [str(r["url"]) for r in self.db.get_endpoints(self.session_id)]))
        for check in self.security_checks:
            if check.mode == "automated" and check.assets:
                before = counts["findings"]
                if any(x in check.description.lower() for x in ("header", "cookie", "hsts", "csp", "cors", "referrer", "x-frame")):
                    for url in check.assets[:5] or urls[:5]:
                        counts["findings"] += await self.run_safe_header_check(url, check)
                counts["automated"] += 1
                if counts["findings"] == before:
                    check.reason = "Observed without a confirmed finding"
            else:
                counts[check.mode] += 1
        return counts

    async def run_all_items(self) -> dict[str, Any]:
        """Evaluate every checklist item with safe automation and explicit gates."""
        plans = self.build_test_plans()
        checks_by_id = {c.check_id: c for c in self.security_checks}
        results = []
        for plan in plans:
            result = {
                "check_id": plan.check_id,
                "checklist_text": plan.checklist_text,
                "family": plan.family,
                "targets": plan.targets,
                "execution_mode": plan.execution_mode,
                "status": "not_applicable" if not plan.targets and plan.execution_mode == "not_applicable" else plan.execution_mode,
                "evidence": [],
                "proof_requirements": plan.proof_requirements,
            }
            if self.tool_router:
                result["adapter"] = self.tool_router.route(plan.family)
            if plan.execution_mode == "automated" and plan.targets:
                check = checks_by_id[plan.check_id]
                for target in plan.targets[:5]:
                    before = self.db.get_finding_count(self.session_id)
                    await self.run_safe_header_check(target, check)
                    result["evidence"].append({"target": target, "new_findings": self.db.get_finding_count(self.session_id) - before})
                result["status"] = "completed"
            elif plan.execution_mode == "manual":
                result["status"] = "approval_required"
                result["steps"] = plan.steps
                result["reason"] = "State-changing or higher-impact execution requires explicit approval."
            elif plan.execution_mode == "blocked":
                result["status"] = "blocked"
                result["steps"] = plan.steps
                result["reason"] = "High-impact execution requires a dedicated isolated adapter and approval."
            results.append(result)
        summary = {"total": len(results)}
        for status in {r["status"] for r in results}:
            summary[status] = sum(r["status"] == status for r in results)
        return {"summary": summary, "results": results}
