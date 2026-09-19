"""
bb_harness.core.db
SQLite persistence layer for targets, findings, and scan results.
"""
import sqlite3
import json
import uuid
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime

from bb_harness.core.config import DB_PATH
from bb_harness.core.models import (
    Subdomain, OpenPort, Technology, Endpoint,
    Parameter, Finding, CheckItem, CheckStatus, ScanSession,
)


class Database:
    """SQLite database for storing all recon data."""

    def __init__(self, db_path: Path | str = DB_PATH):
        if str(db_path) == ":memory:":
            self.db_path = ":memory:"
            self.conn = sqlite3.connect(":memory:")
        else:
            self.db_path = Path(db_path)
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(str(self.db_path))
            self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._create_tables()

    def _create_tables(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                mode TEXT DEFAULT 'host',
                started_at TEXT,
                finished_at TEXT,
                total_checks INTEGER DEFAULT 230,
                completed_checks INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS subdomains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                subdomain TEXT NOT NULL,
                domain TEXT NOT NULL,
                source TEXT,
                ip_addresses TEXT DEFAULT '[]',
                cname TEXT DEFAULT '',
                is_wildcard INTEGER DEFAULT 0,
                is_alive INTEGER DEFAULT 0,
                http_status INTEGER DEFAULT 0,
                http_title TEXT DEFAULT '',
                cdn TEXT DEFAULT '',
                takeover_vulnerable INTEGER DEFAULT 0,
                discovered_at TEXT,
                UNIQUE(session_id, subdomain)
            );

            CREATE TABLE IF NOT EXISTS open_ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT DEFAULT 'tcp',
                service TEXT DEFAULT '',
                version TEXT DEFAULT '',
                banner TEXT DEFAULT '',
                source TEXT DEFAULT '',
                is_default_creds INTEGER DEFAULT 0,
                notes TEXT DEFAULT '',
                discovered_at TEXT,
                UNIQUE(session_id, host, port, protocol)
            );

            CREATE TABLE IF NOT EXISTS technologies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                url TEXT NOT NULL,
                name TEXT NOT NULL,
                version TEXT DEFAULT '',
                category TEXT DEFAULT '',
                confidence INTEGER DEFAULT 100,
                source TEXT DEFAULT '',
                discovered_at TEXT,
                UNIQUE(session_id, url, name)
            );

            CREATE TABLE IF NOT EXISTS endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                url TEXT NOT NULL,
                method TEXT DEFAULT 'GET',
                status_code INTEGER DEFAULT 0,
                content_type TEXT DEFAULT '',
                content_length INTEGER DEFAULT 0,
                source TEXT DEFAULT '',
                is_interesting INTEGER DEFAULT 0,
                notes TEXT DEFAULT '',
                discovered_at TEXT,
                UNIQUE(session_id, url, method)
            );

            CREATE TABLE IF NOT EXISTS parameters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                url TEXT NOT NULL,
                name TEXT NOT NULL,
                param_type TEXT DEFAULT 'query',
                sample_value TEXT DEFAULT '',
                source TEXT DEFAULT '',
                discovered_at TEXT,
                UNIQUE(session_id, url, name, param_type)
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                title TEXT NOT NULL,
                severity TEXT DEFAULT 'info',
                url TEXT DEFAULT '',
                description TEXT DEFAULT '',
                evidence TEXT DEFAULT '',
                source TEXT DEFAULT '',
                check_id TEXT DEFAULT '',
                discovered_at TEXT
            );

            CREATE TABLE IF NOT EXISTS check_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                check_id TEXT NOT NULL,
                category TEXT NOT NULL,
                description TEXT DEFAULT '',
                status TEXT DEFAULT 'pending',
                result_count INTEGER DEFAULT 0,
                error_message TEXT DEFAULT '',
                started_at TEXT,
                finished_at TEXT,
                UNIQUE(session_id, check_id)
            );

            CREATE INDEX IF NOT EXISTS idx_sub_session ON subdomains(session_id);
            CREATE INDEX IF NOT EXISTS idx_sub_domain ON subdomains(domain);
            CREATE INDEX IF NOT EXISTS idx_port_session ON open_ports(session_id);
            CREATE INDEX IF NOT EXISTS idx_tech_session ON technologies(session_id);
            CREATE INDEX IF NOT EXISTS idx_ep_session ON endpoints(session_id);
            CREATE INDEX IF NOT EXISTS idx_param_session ON parameters(session_id);
            CREATE INDEX IF NOT EXISTS idx_finding_session ON findings(session_id);
            CREATE INDEX IF NOT EXISTS idx_check_session ON check_results(session_id);
        """)
        self.conn.commit()

    # ── Session Management ────────────────────────────────────────────────────
    def create_session(self, target: str, mode: str = "host") -> str:
        session_id = str(uuid.uuid4())[:8]
        self.conn.execute(
            "INSERT INTO sessions (session_id, target, mode, started_at) VALUES (?, ?, ?, ?)",
            (session_id, target, mode, datetime.utcnow().isoformat()),
        )
        self.conn.commit()
        return session_id

    def finish_session(self, session_id: str):
        self.conn.execute(
            "UPDATE sessions SET finished_at = ? WHERE session_id = ?",
            (datetime.utcnow().isoformat(), session_id),
        )
        self.conn.commit()

    # ── Subdomain CRUD ────────────────────────────────────────────────────────
    def add_subdomain(self, session_id: str, sub: Subdomain) -> bool:
        try:
            self.conn.execute(
                """INSERT OR IGNORE INTO subdomains
                   (session_id, subdomain, domain, source, ip_addresses, cname,
                    is_wildcard, is_alive, http_status, http_title, cdn,
                    takeover_vulnerable, discovered_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (session_id, sub.subdomain, sub.domain, sub.source,
                 json.dumps(sub.ip_addresses), sub.cname, int(sub.is_wildcard),
                 int(sub.is_alive), sub.http_status, sub.http_title, sub.cdn,
                 int(sub.takeover_vulnerable), sub.discovered_at),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def add_subdomains_bulk(self, session_id: str, subs: List[Subdomain]) -> int:
        added = 0
        for sub in subs:
            if self.add_subdomain(session_id, sub):
                added += 1
        return added

    def get_subdomains(self, session_id: str) -> List[dict]:
        rows = self.conn.execute(
            "SELECT * FROM subdomains WHERE session_id = ? ORDER BY subdomain",
            (session_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def update_subdomain_probe(self, session_id: str, subdomain: str, ip_addresses: list | None = None,
                               is_alive: bool = False, http_status: int = 0, http_title: str = ""):
        """Persist live-host probe results for an existing subdomain."""
        values = [int(is_alive), http_status, http_title]
        sql = "UPDATE subdomains SET is_alive = ?, http_status = ?, http_title = ?"
        if ip_addresses is not None:
            sql += ", ip_addresses = ?"
            values.append(json.dumps(ip_addresses))
        sql += " WHERE session_id = ? AND subdomain = ?"
        values.extend([session_id, subdomain])
        self.conn.execute(sql, values)
        self.conn.commit()

    def get_subdomain_count(self, session_id: str) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) as cnt FROM subdomains WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        return row["cnt"]

    # ── Port CRUD ─────────────────────────────────────────────────────────────
    def add_port(self, session_id: str, port: OpenPort) -> bool:
        try:
            self.conn.execute(
                """INSERT OR IGNORE INTO open_ports
                   (session_id, host, port, protocol, service, version, banner,
                    source, is_default_creds, notes, discovered_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (session_id, port.host, port.port, port.protocol, port.service,
                 port.version, port.banner, port.source, int(port.is_default_creds),
                 port.notes, port.discovered_at),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def get_ports(self, session_id: str) -> List[dict]:
        rows = self.conn.execute(
            "SELECT * FROM open_ports WHERE session_id = ? ORDER BY host, port",
            (session_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_port_count(self, session_id: str) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) as cnt FROM open_ports WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        return row["cnt"]

    # ── Technology CRUD ───────────────────────────────────────────────────────
    def add_technology(self, session_id: str, tech: Technology) -> bool:
        try:
            self.conn.execute(
                """INSERT OR IGNORE INTO technologies
                   (session_id, url, name, version, category, confidence, source, discovered_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (session_id, tech.url, tech.name, tech.version, tech.category,
                 tech.confidence, tech.source, tech.discovered_at),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def get_technologies(self, session_id: str) -> List[dict]:
        rows = self.conn.execute(
            "SELECT * FROM technologies WHERE session_id = ? ORDER BY url, name",
            (session_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_tech_count(self, session_id: str) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) as cnt FROM technologies WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        return row["cnt"]

    # ── Endpoint CRUD ─────────────────────────────────────────────────────────
    def add_endpoint(self, session_id: str, ep: Endpoint) -> bool:
        try:
            self.conn.execute(
                """INSERT OR IGNORE INTO endpoints
                   (session_id, url, method, status_code, content_type, content_length,
                    source, is_interesting, notes, discovered_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (session_id, ep.url, ep.method, ep.status_code, ep.content_type,
                 ep.content_length, ep.source, int(ep.is_interesting), ep.notes,
                 ep.discovered_at),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def get_endpoints(self, session_id: str) -> List[dict]:
        rows = self.conn.execute(
            "SELECT * FROM endpoints WHERE session_id = ? ORDER BY url",
            (session_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_endpoint_count(self, session_id: str) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) as cnt FROM endpoints WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        return row["cnt"]

    # ── Parameter CRUD ────────────────────────────────────────────────────────
    def add_parameter(self, session_id: str, param: Parameter) -> bool:
        try:
            self.conn.execute(
                """INSERT OR IGNORE INTO parameters
                   (session_id, url, name, param_type, sample_value, source, discovered_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (session_id, param.url, param.name, param.param_type,
                 param.sample_value, param.source, param.discovered_at),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def get_parameters(self, session_id: str) -> List[dict]:
        rows = self.conn.execute(
            "SELECT * FROM parameters WHERE session_id = ? ORDER BY url, name",
            (session_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_param_count(self, session_id: str) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) as cnt FROM parameters WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        return row["cnt"]

    # ── Finding CRUD ──────────────────────────────────────────────────────────
    def add_finding(self, session_id: str, finding: Finding) -> bool:
        self.conn.execute(
            """INSERT INTO findings
               (session_id, title, severity, url, description, evidence, source, check_id, discovered_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (session_id, finding.title, finding.severity.value, finding.url,
             finding.description, finding.evidence, finding.source,
             finding.check_id, finding.discovered_at),
        )
        self.conn.commit()
        return True

    def get_findings(self, session_id: str) -> List[dict]:
        rows = self.conn.execute(
            "SELECT * FROM findings WHERE session_id = ? ORDER BY severity DESC, title",
            (session_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_finding_count(self, session_id: str) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) as cnt FROM findings WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        return row["cnt"]

    # ── Check Results ─────────────────────────────────────────────────────────
    def init_checks(self, session_id: str, checks: List[CheckItem]):
        for c in checks:
            self.conn.execute(
                """INSERT OR IGNORE INTO check_results
                   (session_id, check_id, category, description, status)
                   VALUES (?, ?, ?, ?, ?)""",
                (session_id, c.check_id, c.category.value, c.description, c.status.value),
            )
        self.conn.commit()

    def update_check(self, session_id: str, check_id: str, status: CheckStatus,
                     result_count: int = 0, error_message: str = ""):
        now = datetime.utcnow().isoformat()
        if status == CheckStatus.RUNNING:
            self.conn.execute(
                "UPDATE check_results SET status = ?, started_at = ? WHERE session_id = ? AND check_id = ?",
                (status.value, now, session_id, check_id),
            )
        else:
            self.conn.execute(
                """UPDATE check_results SET status = ?, result_count = ?,
                   error_message = ?, finished_at = ?
                   WHERE session_id = ? AND check_id = ?""",
                (status.value, result_count, error_message, now, session_id, check_id),
            )
        self.conn.commit()

    def get_checks(self, session_id: str, category: str = None) -> List[dict]:
        if category:
            rows = self.conn.execute(
                "SELECT * FROM check_results WHERE session_id = ? AND category = ? ORDER BY check_id",
                (session_id, category),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM check_results WHERE session_id = ? ORDER BY check_id",
                (session_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_check_stats(self, session_id: str) -> Dict[str, int]:
        rows = self.conn.execute(
            "SELECT status, COUNT(*) as cnt FROM check_results WHERE session_id = ? GROUP BY status",
            (session_id,),
        ).fetchall()
        return {r["status"]: r["cnt"] for r in rows}

    # ── Summary ───────────────────────────────────────────────────────────────
    def get_summary(self, session_id: str) -> Dict[str, int]:
        stats = self.get_check_stats(session_id)
        return {
            "subdomains": self.get_subdomain_count(session_id),
            "ports": self.get_port_count(session_id),
            "technologies": self.get_tech_count(session_id),
            "endpoints": self.get_endpoint_count(session_id),
            "parameters": self.get_param_count(session_id),
            "findings": self.get_finding_count(session_id),
            "checks_done": stats.get("done", 0),
            "checks_total": sum(stats.values()),
        }

    def close(self):
        self.conn.close()
