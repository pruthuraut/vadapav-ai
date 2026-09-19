"""
bb_harness.core.models
Data models for targets, findings, checks, and scan results.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, Any
from datetime import datetime
from enum import Enum


class CheckStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AgentCategory(str, Enum):
    SUBDOMAIN_ENUM = "subdomain_enum"
    PORT_SCAN = "port_scan"
    TECH_FINGERPRINT = "tech_fingerprint"
    CONTENT_DISCOVERY = "content_discovery"
    LINK_PARAM_DISCOVERY = "link_param_discovery"


@dataclass
class CheckItem:
    """A single methodology check (one of the 230 items)."""
    check_id: str                       # e.g. "sub_001"
    category: AgentCategory
    description: str
    tool_name: str = ""                 # Primary tool required
    requires_api_key: str = ""          # API key field name from config
    status: CheckStatus = CheckStatus.PENDING
    result_count: int = 0
    error_message: str = ""
    started_at: Optional[str] = None
    finished_at: Optional[str] = None


@dataclass
class Subdomain:
    """A discovered subdomain."""
    subdomain: str
    domain: str
    source: str                         # Which check discovered it
    ip_addresses: list = field(default_factory=list)
    cname: str = ""
    is_wildcard: bool = False
    is_alive: bool = False
    http_status: int = 0
    http_title: str = ""
    cdn: str = ""
    takeover_vulnerable: bool = False
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class OpenPort:
    """A discovered open port on a host."""
    host: str
    port: int
    protocol: str = "tcp"
    service: str = ""
    version: str = ""
    banner: str = ""
    source: str = ""
    is_default_creds: bool = False
    notes: str = ""
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class Technology:
    """A fingerprinted technology on a target."""
    url: str
    name: str                           # e.g. "WordPress", "React", "Nginx"
    version: str = ""
    category: str = ""                  # e.g. "CMS", "JS Framework", "CDN"
    confidence: int = 100
    source: str = ""
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class Endpoint:
    """A discovered URL/endpoint/path."""
    url: str
    method: str = "GET"
    status_code: int = 0
    content_type: str = ""
    content_length: int = 0
    source: str = ""
    is_interesting: bool = False
    notes: str = ""
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class Parameter:
    """A discovered parameter on an endpoint."""
    url: str
    name: str
    param_type: str = "query"           # query, path, body, header, cookie
    sample_value: str = ""
    source: str = ""
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class Finding:
    """A vulnerability or interesting finding."""
    title: str
    severity: Severity = Severity.INFO
    url: str = ""
    description: str = ""
    evidence: str = ""
    source: str = ""
    check_id: str = ""
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class ScanSession:
    """Represents one scan session against a target."""
    session_id: str = ""
    target: str = ""
    mode: str = "host"
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    finished_at: Optional[str] = None
    total_checks: int = 230
    completed_checks: int = 0
    subdomains_found: int = 0
    ports_found: int = 0
    endpoints_found: int = 0
    technologies_found: int = 0
    findings_found: int = 0
