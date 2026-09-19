"""
bb_harness.agents.content_discovery
Content & URL Discovery Agent — 50 checks.
"""
from __future__ import annotations
import re
import asyncio
from typing import Optional, List

from bb_harness.agents.base import BaseAgent
from bb_harness.core.models import (
    AgentCategory, Endpoint, Finding, Severity,
)


class ContentDiscoveryAgent(BaseAgent):
    AGENT_ID = "content_discovery"
    CATEGORY = AgentCategory.CONTENT_DISCOVERY
    NAME = "Content & URL Discovery"
    DESCRIPTION = "50 checks for finding hidden files, directories, endpoints, and sensitive data"

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _probe_paths(self, paths: List[str], source: str,
                           check_id: str, severity: Severity = Severity.MEDIUM,
                           fingerprints: List[str] = None) -> int:
        """Probe multiple paths and store findings for any that exist."""
        count = 0
        for path in paths:
            for scheme in ["https", "http"]:
                try:
                    resp = await self.http_get(
                        f"{scheme}://{self.target}{path}", timeout=10)
                    if resp and resp["status"] in range(200, 400):
                        text = resp.get("text", "")
                        if fingerprints:
                            if not any(fp.lower() in text.lower() for fp in fingerprints):
                                continue
                        self.db.add_endpoint(self.session_id, Endpoint(
                            url=f"{scheme}://{self.target}{path}",
                            status_code=resp["status"],
                            content_type=resp.get("headers", {}).get("content-type", ""),
                            content_length=len(text),
                            source=source,
                            is_interesting=True,
                            notes=f"Found by {source}",
                        ))
                        self.db.add_finding(self.session_id, Finding(
                            title=f"Sensitive path found: {path}",
                            severity=severity,
                            url=f"{scheme}://{self.target}{path}",
                            description=f"HTTP {resp['status']} — {len(text)} bytes",
                            source=source,
                            check_id=check_id,
                        ))
                        count += 1
                        break  # found on this scheme, skip other
                except Exception:
                    pass
        return count

    # ══════════════════════════════════════════════════════════════════════════
    # CHECK IMPLEMENTATIONS
    # ══════════════════════════════════════════════════════════════════════════

    async def _run_cont_001(self) -> int:
        """ffuf — fast directory and file fuzzing."""
        result = await self.run_tool(
            "ffuf",
            f"ffuf -u https://{self.target}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,403 -o - -of csv -noninteractive",
            timeout=300,
        )
        if result.success:
            count = 0
            for line in result.lines:
                parts = line.split(",")
                if len(parts) >= 3 and parts[0] not in ["", "FUZZ"]:
                    self.db.add_endpoint(self.session_id, Endpoint(
                        url=f"https://{self.target}/{parts[0]}",
                        status_code=int(parts[2]) if parts[2].isdigit() else 0,
                        source="ffuf",
                    ))
                    count += 1
            return count
        return 0

    async def _run_cont_002(self) -> int:
        """gobuster — directory/file brute forcing."""
        result = await self.run_tool(
            "gobuster",
            f"gobuster dir -u https://{self.target} -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 20 -q --no-color",
            timeout=300,
        )
        if result.success:
            count = 0
            for line in result.lines:
                m = re.search(r"(/\S+)\s+\(Status:\s+(\d+)\)", line)
                if m:
                    self.db.add_endpoint(self.session_id, Endpoint(
                        url=f"https://{self.target}{m.group(1)}",
                        status_code=int(m.group(2)),
                        source="gobuster",
                    ))
                    count += 1
            return count
        return 0

    async def _run_cont_003(self) -> int:
        """dirsearch — recursive directory scanning."""
        result = await self.run_tool(
            "dirsearch",
            f"dirsearch -u https://{self.target} -e php,asp,aspx,jsp,html,js -t 20 --format=plain --quiet-mode",
            timeout=300,
        )
        if result.success:
            count = 0
            for line in result.lines:
                m = re.search(r"(\d{3})\s+\S+\s+(\S+)", line)
                if m:
                    self.db.add_endpoint(self.session_id, Endpoint(
                        url=m.group(2), status_code=int(m.group(1)), source="dirsearch",
                    ))
                    count += 1
            return count
        return 0

    async def _run_cont_004(self) -> int:
        """feroxbuster — recursive content discovery."""
        result = await self.run_tool(
            "feroxbuster",
            f"feroxbuster -u https://{self.target} -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 20 -q --no-state",
            timeout=300,
        )
        if result.success:
            count = 0
            for line in result.lines:
                m = re.search(r"(\d{3})\s+\S+\s+\S+\s+(https?://\S+)", line)
                if m:
                    self.db.add_endpoint(self.session_id, Endpoint(
                        url=m.group(2), status_code=int(m.group(1)), source="feroxbuster",
                    ))
                    count += 1
            return count
        return 0

    async def _run_cont_005(self) -> int:
        """Check robots.txt and analyze disallowed entries."""
        count = 0
        for scheme in ["https", "http"]:
            resp = await self.http_get(f"{scheme}://{self.target}/robots.txt", timeout=10)
            if resp and resp["status"] == 200 and ("Disallow" in resp["text"] or "Allow" in resp["text"]):
                self.db.add_endpoint(self.session_id, Endpoint(
                    url=f"{scheme}://{self.target}/robots.txt",
                    status_code=200, source="robots_txt", is_interesting=True,
                ))
                disallowed = re.findall(r"Disallow:\s*(\S+)", resp["text"])
                for path in disallowed:
                    self.db.add_endpoint(self.session_id, Endpoint(
                        url=f"{scheme}://{self.target}{path}",
                        source="robots_txt_disallow", is_interesting=True,
                        notes=f"Disallowed in robots.txt",
                    ))
                    count += 1
                break
        return count

    async def _run_cont_006(self) -> int:
        """Check sitemap.xml for hidden URLs."""
        count = 0
        for path in ["/sitemap.xml", "/sitemap_index.xml", "/sitemap.txt"]:
            for scheme in ["https", "http"]:
                resp = await self.http_get(f"{scheme}://{self.target}{path}", timeout=10)
                if resp and resp["status"] == 200:
                    urls = re.findall(r"<loc>([^<]+)</loc>", resp["text"])
                    urls += re.findall(r"(https?://[^\s]+)", resp["text"])
                    for url in set(urls):
                        self.db.add_endpoint(self.session_id, Endpoint(
                            url=url, source="sitemap",
                        ))
                        count += 1
                    break
        return count

    async def _run_cont_007(self) -> int:
        """Check .well-known/ directory."""
        well_known_paths = [
            "/.well-known/security.txt",
            "/.well-known/assetlinks.json",
            "/.well-known/change-password",
            "/.well-known/openid-configuration",
            "/.well-known/apple-app-site-association",
            "/.well-known/oauth-authorization-server",
        ]
        return await self._probe_paths(well_known_paths, "well_known", "cont_007", Severity.INFO)

    async def _run_cont_008(self) -> int:
        """Look for backup files."""
        base = self.target.split(".")[0]
        backup_paths = [
            f"/{base}.bak", f"/{base}.old", f"/{base}.zip", f"/{base}.tar.gz",
            "/backup.zip", "/backup.sql", "/backup.tar.gz",
            "/db.sql", "/database.sql", "/dump.sql",
            "/site.zip", "/www.zip", "/web.zip",
        ]
        return await self._probe_paths(backup_paths, "backup_files", "cont_008", Severity.HIGH)

    async def _run_cont_009(self) -> int:
        """Check for configuration files."""
        config_paths = [
            "/.env", "/.env.local", "/.env.production", "/.env.backup",
            "/.htaccess", "/.htpasswd",
            "/web.config", "/app.config", "/config.yml", "/config.yaml",
            "/wp-config.php.bak", "/configuration.php",
            "/config/database.yml", "/config/secrets.yml",
        ]
        return await self._probe_paths(config_paths, "config_files", "cont_009", Severity.CRITICAL)

    async def _run_cont_010(self) -> int:
        """Look for source code repositories."""
        repo_paths = [
            "/.git/HEAD", "/.git/config",
            "/.svn/entries", "/.svn/wc.db",
            "/.hg/store/00changelog.i",
            "/.bzr/README",
        ]
        return await self._probe_paths(repo_paths, "source_repos", "cont_010", Severity.CRITICAL)

    async def _run_cont_011(self) -> int:
        """Check for exposed .git directory."""
        git_paths = ["/.git/HEAD", "/.git/config", "/.git/index",
                     "/.git/FETCH_HEAD", "/.git/description"]
        return await self._probe_paths(git_paths, "git_exposure", "cont_011", Severity.CRITICAL)

    async def _run_cont_012(self) -> int:
        """Search for .DS_Store files."""
        return await self._probe_paths(
            ["/.DS_Store", "/admin/.DS_Store", "/images/.DS_Store"],
            "ds_store", "cont_012", Severity.LOW)

    async def _run_cont_013(self) -> int:
        """Check for wp-config.php, config.php, database.yml exposure."""
        return await self._probe_paths(
            ["/wp-config.php", "/wp-config.php.bak", "/wp-config.php~",
             "/config.php", "/database.yml", "/settings.py"],
            "config_exposure", "cont_013", Severity.CRITICAL)

    async def _run_cont_014(self) -> int:
        """Look for backup archives."""
        base = self.target.replace(".", "_")
        return await self._probe_paths(
            [f"/{base}.zip", f"/{base}.tar.gz", f"/{base}.rar",
             "/backup.zip", "/archive.zip", "/site.zip", "/www.tar.gz"],
            "backup_archives", "cont_014", Severity.HIGH)

    async def _run_cont_015(self) -> int:
        """Search for log files."""
        return await self._probe_paths(
            ["/error.log", "/access.log", "/debug.log", "/application.log",
             "/logs/error.log", "/logs/access.log", "/log.txt",
             "/var/log/", "/storage/logs/laravel.log"],
            "log_files", "cont_015", Severity.HIGH)

    async def _run_cont_016(self) -> int:
        """Check for debug endpoints."""
        return await self._probe_paths(
            ["/debug", "/trace", "/status", "/healthz", "/health",
             "/info", "/_debug", "/server-info", "/server-status",
             "/elmah.axd", "/phpinfo.php"],
            "debug_endpoints", "cont_016", Severity.MEDIUM)

    async def _run_cont_017(self) -> int:
        """Look for test files."""
        return await self._probe_paths(
            ["/test.php", "/test.html", "/info.php", "/phpinfo.php",
             "/test.asp", "/test.aspx", "/test.jsp", "/test.txt"],
            "test_files", "cont_017", Severity.LOW)

    async def _run_cont_018(self) -> int:
        """Check for API documentation."""
        return await self._probe_paths(
            ["/api-docs", "/swagger", "/swagger-ui/", "/swagger-ui.html",
             "/redoc", "/graphql", "/api/v1/", "/api/v2/",
             "/openapi.json", "/swagger.json"],
            "api_docs", "cont_018", Severity.INFO)

    async def _run_cont_019(self) -> int:
        """Look for admin panels."""
        return await self._probe_paths(
            ["/admin", "/admin/", "/administrator", "/administrator/",
             "/manager", "/cpanel", "/backend", "/dashboard",
             "/admin/login", "/admin/dashboard"],
            "admin_panels", "cont_019", Severity.MEDIUM)

    async def _run_cont_020(self) -> int:
        """Check for phpMyAdmin."""
        return await self._probe_paths(
            ["/phpmyadmin/", "/pma/", "/dbadmin/", "/mysql/",
             "/phpmyadmin/index.php", "/phpMyAdmin/"],
            "phpmyadmin", "cont_020", Severity.HIGH,
            fingerprints=["phpmyadmin", "phpMyAdmin"])

    async def _run_cont_021(self) -> int:
        """Look for CMS admin."""
        return await self._probe_paths(
            ["/wp-admin/", "/wp-login.php", "/administrator/index.php",
             "/user/login", "/admin/login"],
            "cms_admin", "cont_021", Severity.MEDIUM)

    async def _run_cont_022(self) -> int:
        """Check for staging/dev environments."""
        subs = self.db.get_subdomains(self.session_id)
        count = 0
        dev_prefixes = ["dev", "staging", "test", "uat", "preprod", "qa",
                        "beta", "alpha", "sandbox", "demo"]
        for prefix in dev_prefixes:
            fqdn = f"{prefix}.{self.target}"
            ips = await self.resolve_dns(fqdn)
            if ips:
                self.db.add_finding(self.session_id, Finding(
                    title=f"Dev/staging environment found: {fqdn}",
                    severity=Severity.MEDIUM,
                    url=f"https://{fqdn}",
                    description=f"Resolves to: {', '.join(ips)}",
                    source="dev_env", check_id="cont_022",
                ))
                count += 1
        return count

    async def _run_cont_023(self) -> int:
        """Search for publicly accessible Google Docs/Sheets."""
        resp = await self.http_get(
            f"https://html.duckduckgo.com/html/?q=site:docs.google.com+%22{self.target}%22")
        if resp and resp["status"] == 200:
            urls = re.findall(r'(https://docs\.google\.com/[^\s"\']+)', resp["text"])
            count = 0
            for url in set(urls)[:10]:
                self.db.add_finding(self.session_id, Finding(
                    title="Public Google Doc referencing target",
                    severity=Severity.LOW,
                    url=url,
                    source="google_docs", check_id="cont_023",
                ))
                count += 1
            return count
        return 0

    async def _run_cont_024(self) -> int:
        """waybackurls — historical URL discovery."""
        result = await self.run_tool(
            "waybackurls", f"echo {self.target} | waybackurls", timeout=120)
        if result.success:
            count = 0
            for url in result.lines[:500]:
                self.db.add_endpoint(self.session_id, Endpoint(
                    url=url.strip(), source="waybackurls",
                ))
                count += 1
            return count
        # Fallback: use Wayback CDX API
        resp = await self.http_get(
            f"https://web.archive.org/cdx/search/cdx?url={self.target}/*&output=text&fl=original&collapse=urlkey&limit=500",
            timeout=30,
        )
        if resp and resp["status"] == 200:
            count = 0
            for url in resp["text"].splitlines()[:500]:
                url = url.strip()
                if url:
                    self.db.add_endpoint(self.session_id, Endpoint(
                        url=url, source="wayback_cdx",
                    ))
                    count += 1
            return count
        return 0

    async def _run_cont_025(self) -> int:
        """gau — URLs from AlienVault, Wayback, Common Crawl."""
        result = await self.run_tool(
            "gau", f"echo {self.target} | gau --threads 5", timeout=120)
        if result.success:
            count = 0
            for url in result.lines[:500]:
                self.db.add_endpoint(self.session_id, Endpoint(
                    url=url.strip(), source="gau",
                ))
                count += 1
            return count
        # Fallback: AlienVault OTX
        data = await self.http_get_json(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{self.target}/url_list?limit=200")
        if data and "url_list" in data:
            count = 0
            for entry in data["url_list"]:
                self.db.add_endpoint(self.session_id, Endpoint(
                    url=entry.get("url", ""), source="alienvault_otx",
                ))
                count += 1
            return count
        return 0

    async def _run_cont_026(self) -> int:
        """Extract URLs and endpoints from JavaScript files."""
        resp = await self.http_get(f"https://{self.target}", timeout=15)
        if not resp:
            resp = await self.http_get(f"http://{self.target}", timeout=15)
        if not resp:
            return 0
        # Find JS file URLs
        js_urls = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', resp["text"])
        count = 0
        for js_url in js_urls[:30]:
            if js_url.startswith("//"):
                js_url = "https:" + js_url
            elif js_url.startswith("/"):
                js_url = f"https://{self.target}{js_url}"
            elif not js_url.startswith("http"):
                js_url = f"https://{self.target}/{js_url}"
            js_resp = await self.http_get(js_url, timeout=10)
            if js_resp and js_resp["status"] == 200:
                # Extract endpoints from JS
                endpoints = re.findall(
                    r'["\'](/(?:api|v[0-9]|graphql|auth|user|admin|login|signup|register|search|upload|download|export|webhook)[^\s"\']*)["\']',
                    js_resp["text"], re.I)
                for ep in set(endpoints):
                    self.db.add_endpoint(self.session_id, Endpoint(
                        url=f"https://{self.target}{ep}",
                        source="js_extraction", is_interesting=True,
                    ))
                    count += 1
        return count

    async def _run_cont_027(self) -> int:
        """Check for .env file exposure."""
        return await self._probe_paths(
            ["/.env", "/.env.local", "/.env.production", "/.env.development",
             "/.env.backup", "/.env.old", "/.env.example"],
            "env_file", "cont_027", Severity.CRITICAL)

    async def _run_cont_028(self) -> int:
        """Look for docker-compose.yml and Dockerfile exposure."""
        return await self._probe_paths(
            ["/docker-compose.yml", "/docker-compose.yaml",
             "/Dockerfile", "/.dockerignore"],
            "docker_files", "cont_028", Severity.HIGH)

    async def _run_cont_029(self) -> int:
        """Check for package.json, composer.json, requirements.txt exposure."""
        return await self._probe_paths(
            ["/package.json", "/package-lock.json", "/composer.json",
             "/composer.lock", "/requirements.txt", "/Pipfile",
             "/Gemfile", "/go.mod", "/pom.xml", "/build.gradle"],
            "dependency_files", "cont_029", Severity.MEDIUM)

    async def _run_cont_030(self) -> int:
        """Search for .htpasswd files."""
        return await self._probe_paths(
            ["/.htpasswd", "/admin/.htpasswd", "/private/.htpasswd"],
            "htpasswd", "cont_030", Severity.CRITICAL)

    async def _run_cont_031(self) -> int:
        """Look for database dump files."""
        base = self.target.split(".")[0]
        return await self._probe_paths(
            ["/dump.sql", f"/{base}.sql", "/database.sql", "/db.sql",
             "/backup.sql", f"/{base}.db", "/data.sqlite"],
            "db_dumps", "cont_031", Severity.CRITICAL)

    async def _run_cont_032(self) -> int:
        """Check for Jenkins script console."""
        return await self._probe_paths(
            ["/script", "/jenkins/script", "/manage"],
            "jenkins_script", "cont_032", Severity.CRITICAL,
            fingerprints=["Jenkins", "script console"])

    async def _run_cont_033(self) -> int:
        """Look for exposed Grafana dashboards."""
        count = 0
        for port in [3000, 80, 443]:
            resp = await self.http_get(f"http://{self.target}:{port}/grafana/", timeout=8)
            if resp and resp["status"] in range(200, 400) and "grafana" in resp.get("text", "").lower():
                self.db.add_finding(self.session_id, Finding(
                    title=f"Grafana dashboard found on port {port}",
                    severity=Severity.MEDIUM,
                    url=f"http://{self.target}:{port}/grafana/",
                    source="grafana_check", check_id="cont_033",
                ))
                count += 1
        return count

    async def _run_cont_034(self) -> int:
        """Check for Prometheus metrics endpoint."""
        return await self._probe_paths(
            ["/metrics", "/prometheus/metrics"],
            "prometheus_metrics", "cont_034", Severity.MEDIUM,
            fingerprints=["# HELP", "# TYPE", "process_"])

    async def _run_cont_035(self) -> int:
        """Look for Kibana dashboard."""
        resp = await self.http_get(f"http://{self.target}:5601/", timeout=8)
        if resp and resp["status"] in range(200, 400) and "kibana" in resp.get("text", "").lower():
            self.db.add_finding(self.session_id, Finding(
                title=f"Kibana dashboard accessible on port 5601",
                severity=Severity.HIGH,
                url=f"http://{self.target}:5601/",
                source="kibana_check", check_id="cont_035",
            ))
            return 1
        return 0

    async def _run_cont_036(self) -> int:
        """Check for Airflow web UI."""
        resp = await self.http_get(f"http://{self.target}:8080/", timeout=8)
        if resp and "airflow" in resp.get("text", "").lower():
            self.db.add_finding(self.session_id, Finding(
                title="Apache Airflow UI found",
                severity=Severity.HIGH,
                url=f"http://{self.target}:8080/",
                source="airflow_check", check_id="cont_036",
            ))
            return 1
        return 0

    async def _run_cont_037(self) -> int:
        """Look for RabbitMQ management with default creds."""
        resp = await self.http_get(f"http://{self.target}:15672/", timeout=8)
        if resp and "rabbitmq" in resp.get("text", "").lower():
            self.db.add_finding(self.session_id, Finding(
                title="RabbitMQ management UI found",
                severity=Severity.MEDIUM,
                url=f"http://{self.target}:15672/",
                source="rabbitmq_check", check_id="cont_037",
            ))
            return 1
        return 0

    async def _run_cont_038(self) -> int:
        """Check for Solr admin."""
        resp = await self.http_get(f"http://{self.target}:8983/solr/", timeout=8)
        if resp and "solr" in resp.get("text", "").lower():
            self.db.add_finding(self.session_id, Finding(
                title="Apache Solr admin found",
                severity=Severity.HIGH,
                url=f"http://{self.target}:8983/solr/",
                source="solr_check", check_id="cont_038",
            ))
            return 1
        return 0

    async def _run_cont_039(self) -> int:
        """Look for MinIO console."""
        resp = await self.http_get(f"http://{self.target}:9001/", timeout=8)
        if resp and "minio" in resp.get("text", "").lower():
            self.db.add_finding(self.session_id, Finding(
                title="MinIO console found",
                severity=Severity.MEDIUM,
                url=f"http://{self.target}:9001/",
                source="minio_check", check_id="cont_039",
            ))
            return 1
        return 0

    async def _run_cont_040(self) -> int:
        """Check for Apache Tomcat manager."""
        return await self._probe_paths(
            ["/manager/html", "/manager/status", "/host-manager/html"],
            "tomcat_manager", "cont_040", Severity.HIGH,
            fingerprints=["tomcat", "manager", "Apache Tomcat"])

    async def _run_cont_041(self) -> int:
        """Look for JBoss admin console."""
        return await self._probe_paths(
            ["/admin-console/", "/jmx-console/", "/web-console/"],
            "jboss_admin", "cont_041", Severity.HIGH,
            fingerprints=["jboss", "JBoss", "wildfly"])

    async def _run_cont_042(self) -> int:
        """Check for WebLogic admin."""
        return await self._probe_paths(
            ["/console/", "/console/login/LoginForm.jsp"],
            "weblogic_admin", "cont_042", Severity.HIGH,
            fingerprints=["weblogic", "WebLogic", "Oracle"])

    async def _run_cont_043(self) -> int:
        """Look for IBM WebSphere admin."""
        return await self._probe_paths(
            ["/ibm/console/", "/admin/"],
            "websphere_admin", "cont_043", Severity.HIGH,
            fingerprints=["websphere", "WebSphere", "IBM"])

    async def _run_cont_044(self) -> int:
        """Check for Confluence admin."""
        return await self._probe_paths(
            ["/admin/", "/wiki/", "/confluence/"],
            "confluence_admin", "cont_044", Severity.MEDIUM,
            fingerprints=["confluence", "Confluence", "Atlassian"])

    async def _run_cont_045(self) -> int:
        """Look for Jira admin."""
        return await self._probe_paths(
            ["/secure/admin/", "/jira/", "/secure/Dashboard.jspa"],
            "jira_admin", "cont_045", Severity.MEDIUM,
            fingerprints=["jira", "JIRA", "Atlassian"])

    async def _run_cont_046(self) -> int:
        """Check for .well-known/openid-configuration."""
        return await self._probe_paths(
            ["/.well-known/openid-configuration"],
            "openid_config", "cont_046", Severity.INFO)

    async def _run_cont_047(self) -> int:
        """Look for .well-known/oauth-authorization-server."""
        return await self._probe_paths(
            ["/.well-known/oauth-authorization-server"],
            "oauth_config", "cont_047", Severity.INFO)

    async def _run_cont_048(self) -> int:
        """Check for assetlinks.json."""
        return await self._probe_paths(
            ["/.well-known/assetlinks.json"],
            "assetlinks", "cont_048", Severity.INFO)

    async def _run_cont_049(self) -> int:
        """Look for apple-app-site-association."""
        return await self._probe_paths(
            ["/.well-known/apple-app-site-association",
             "/apple-app-site-association"],
            "apple_aasa", "cont_049", Severity.INFO)

    async def _run_cont_050(self) -> int:
        """Check for security.txt."""
        return await self._probe_paths(
            ["/.well-known/security.txt", "/security.txt"],
            "security_txt", "cont_050", Severity.INFO)
