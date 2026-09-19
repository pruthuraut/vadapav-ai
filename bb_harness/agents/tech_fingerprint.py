"""
bb_harness.agents.tech_fingerprint
Technology Fingerprinting Agent — 40 checks.
"""
from __future__ import annotations
import re
from typing import Optional

from bb_harness.agents.base import BaseAgent
from bb_harness.core.models import (
    AgentCategory, Technology, Finding, Severity, Endpoint,
)


class TechFingerprintAgent(BaseAgent):
    AGENT_ID = "tech_fingerprint"
    CATEGORY = AgentCategory.TECH_FINGERPRINT
    NAME = "Technology Fingerprinting"
    DESCRIPTION = "40 checks for identifying web technologies, frameworks, CDNs, and WAFs"

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _fetch_target(self) -> Optional[dict]:
        """Fetch the main target page."""
        resp = await self.http_get(f"https://{self.target}", timeout=15)
        if not resp or resp["status"] == 0:
            resp = await self.http_get(f"http://{self.target}", timeout=15)
        return resp

    async def _add_tech(self, name: str, category: str, version: str = "",
                        confidence: int = 100, source: str = "") -> bool:
        return self.db.add_technology(self.session_id, Technology(
            url=f"https://{self.target}",
            name=name, version=version, category=category,
            confidence=confidence, source=source,
        ))

    async def _check_path_exists(self, path: str, fingerprints: list = None,
                                 timeout: int = 10) -> Optional[dict]:
        """Check if a path exists on the target and optionally match fingerprints."""
        for scheme in ["https", "http"]:
            resp = await self.http_get(f"{scheme}://{self.target}{path}", timeout=timeout)
            if resp and resp["status"] in range(200, 400):
                if fingerprints:
                    text = resp.get("text", "")
                    for fp in fingerprints:
                        if fp.lower() in text.lower():
                            return resp
                else:
                    return resp
        return None

    # ══════════════════════════════════════════════════════════════════════════
    # CHECK IMPLEMENTATIONS
    # ══════════════════════════════════════════════════════════════════════════

    async def _run_tech_001(self) -> int:
        """Wappalyzer-style tech detection (pure Python header/HTML analysis)."""
        resp = await self._fetch_target()
        if not resp:
            return 0
        count = 0
        headers = resp.get("headers", {})
        text = resp.get("text", "")

        # Server header
        server = headers.get("server", "")
        if server:
            await self._add_tech(server.split("/")[0], "Web Server",
                                 version=server.split("/")[1] if "/" in server else "",
                                 source="wappalyzer_headers")
            count += 1
        # X-Powered-By
        xpb = headers.get("x-powered-by", "")
        if xpb:
            await self._add_tech(xpb, "Backend", source="wappalyzer_headers")
            count += 1
        # Generator meta tag
        gen = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', text, re.I)
        if gen:
            await self._add_tech(gen.group(1), "CMS", source="wappalyzer_meta")
            count += 1
        return count

    async def _run_tech_002(self) -> int:
        """whatweb — command-line tech fingerprinting."""
        result = await self.run_tool(
            "whatweb", f"whatweb -a 3 --color=never https://{self.target}", timeout=60)
        if result.success:
            # Parse whatweb output
            techs = re.findall(r"\[(\d+)\]\s+(.+)", result.output)
            count = 0
            for _, tech_list in techs:
                for tech in tech_list.split(","):
                    tech = tech.strip().split("[")[0].strip()
                    if tech:
                        await self._add_tech(tech, "General", source="whatweb")
                        count += 1
            return count
        return 0

    async def _run_tech_003(self) -> int:
        """webanalyze — Go-based Wappalyzer."""
        result = await self.run_tool(
            "webanalyze", f"webanalyze -host https://{self.target} -output json", timeout=60)
        if result.success:
            import json
            try:
                data = json.loads(result.output)
                count = 0
                for item in data:
                    for match in item.get("matches", []):
                        await self._add_tech(
                            match.get("app_name", ""), match.get("cat_name", ""),
                            version=match.get("version", ""), source="webanalyze")
                        count += 1
                return count
            except Exception:
                pass
        return 0

    async def _run_tech_004(self) -> int:
        """Check HTTP response headers for server version disclosure."""
        resp = await self._fetch_target()
        if not resp:
            return 0
        headers = resp.get("headers", {})
        disclosure_headers = ["server", "x-powered-by", "x-aspnet-version",
                              "x-aspnetmvc-version", "x-generator"]
        count = 0
        for h in disclosure_headers:
            val = headers.get(h, "")
            if val:
                self.db.add_finding(self.session_id, Finding(
                    title=f"Version disclosure in {h} header: {val}",
                    severity=Severity.LOW,
                    url=f"https://{self.target}",
                    description=f"{h}: {val}",
                    source="header_disclosure", check_id="tech_004",
                ))
                count += 1
        return count

    async def _run_tech_005(self) -> int:
        """Check X-Powered-By header for backend identification."""
        resp = await self._fetch_target()
        if not resp:
            return 0
        xpb = resp.get("headers", {}).get("x-powered-by", "")
        if xpb:
            await self._add_tech(xpb, "Backend Framework", source="x-powered-by")
            return 1
        return 0

    async def _run_tech_006(self) -> int:
        """Analyze cookies for framework indicators."""
        resp = await self._fetch_target()
        if not resp:
            return 0
        cookies = resp.get("headers", {}).get("set-cookie", "")
        indicators = {
            "PHPSESSID": ("PHP", "Backend Language"),
            "JSESSIONID": ("Java/JSP", "Backend Language"),
            "ASP.NET_SessionId": ("ASP.NET", "Backend Framework"),
            "csrftoken": ("Django", "Backend Framework"),
            "laravel_session": ("Laravel", "Backend Framework"),
            "rack.session": ("Ruby/Rails", "Backend Framework"),
            "connect.sid": ("Express.js/Node", "Backend Framework"),
            "_session_id": ("Rails", "Backend Framework"),
            "ci_session": ("CodeIgniter", "Backend Framework"),
            "CAKEPHP": ("CakePHP", "Backend Framework"),
        }
        count = 0
        for marker, (tech, cat) in indicators.items():
            if marker.lower() in cookies.lower():
                await self._add_tech(tech, cat, source="cookie_analysis")
                count += 1
        return count

    async def _run_tech_007(self) -> int:
        """Check for framework-specific meta tags and generator tags."""
        resp = await self._fetch_target()
        if not resp:
            return 0
        text = resp.get("text", "")
        count = 0
        # Generator tags
        generators = re.findall(
            r'<meta\s+(?:name|property)=["\'](?:generator|application-name)["\']\s+content=["\']([^"\']+)["\']',
            text, re.I)
        for g in generators:
            await self._add_tech(g, "CMS/Framework", source="meta_tag")
            count += 1
        return count

    async def _run_tech_008(self) -> int:
        """Identify CMS using WPScan, Joomscan, Droopescan."""
        count = 0
        # Try WPScan
        result = await self.run_tool(
            "wpscan", f"wpscan --url https://{self.target} --enumerate --no-update", timeout=300)
        if result.success and "WordPress" in result.output:
            ver = re.search(r"WordPress version\s+([\d\.]+)", result.output)
            await self._add_tech("WordPress", "CMS",
                                 version=ver.group(1) if ver else "", source="wpscan")
            count += 1
        # Fallback: check /wp-login.php
        resp = await self._check_path_exists("/wp-login.php", ["wordpress"])
        if resp:
            await self._add_tech("WordPress", "CMS", source="path_check")
            count += 1
        # Check Joomla
        resp = await self._check_path_exists("/administrator/", ["joomla"])
        if resp:
            await self._add_tech("Joomla", "CMS", source="path_check")
            count += 1
        # Check Drupal
        resp = await self._check_path_exists("/core/misc/drupal.js", ["drupal"])
        if resp:
            await self._add_tech("Drupal", "CMS", source="path_check")
            count += 1
        return count

    async def _run_tech_009(self) -> int:
        """Detect JS frameworks via source code analysis."""
        resp = await self._fetch_target()
        if not resp:
            return 0
        text = resp.get("text", "")
        count = 0
        js_frameworks = {
            "react": [r"react\.production", r"_react", r"reactRootContainer", r"__REACT"],
            "angular": [r"ng-version", r"ng-app", r"_nghost", r"angular\.js"],
            "vue": [r"__vue__", r"data-v-", r"Vue\.config", r"vuex"],
            "svelte": [r"svelte-", r"__svelte"],
            "jquery": [r"jQuery", r"jquery\.min\.js"],
            "bootstrap": [r"bootstrap\.min", r"bootstrap\.css"],
        }
        for framework, patterns in js_frameworks.items():
            for pattern in patterns:
                if re.search(pattern, text, re.I):
                    await self._add_tech(framework.title(), "JS Framework", source="js_analysis")
                    count += 1
                    break
        return count

    async def _run_tech_010(self) -> int:
        """Check for React indicators."""
        resp = await self._fetch_target()
        if not resp:
            return 0
        text = resp.get("text", "")
        indicators = ["__NEXT_DATA__", "_reactRootContainer", "react-root",
                       "data-reactroot", "__REACT_DEVTOOLS"]
        for ind in indicators:
            if ind in text:
                await self._add_tech("React", "JS Framework", source="react_indicator")
                return 1
        return 0

    async def _run_tech_011(self) -> int:
        """Check for Angular indicators."""
        resp = await self._fetch_target()
        if not resp:
            return 0
        text = resp.get("text", "")
        indicators = ["ng-version", "ng-app", "_nghost", "ng-controller", "angular.js"]
        for ind in indicators:
            if ind in text.lower():
                ver = re.search(r'ng-version=["\']([^"\']+)["\']', text)
                await self._add_tech("Angular", "JS Framework",
                                     version=ver.group(1) if ver else "",
                                     source="angular_indicator")
                return 1
        return 0

    async def _run_tech_012(self) -> int:
        """Check for Vue.js indicators."""
        resp = await self._fetch_target()
        if not resp:
            return 0
        text = resp.get("text", "")
        if any(ind in text for ind in ["__vue__", "data-v-", "Vue.config", "__VUE__"]):
            await self._add_tech("Vue.js", "JS Framework", source="vue_indicator")
            return 1
        return 0

    async def _run_tech_013(self) -> int:
        """Identify backend language from error messages and extensions."""
        count = 0
        # Trigger potential error pages
        for path in ["/doesnotexist.php", "/doesnotexist.aspx", "/doesnotexist.jsp"]:
            resp = await self.http_get(f"https://{self.target}{path}", timeout=10)
            if resp:
                text = resp.get("text", "")
                if "PHP" in text or "Fatal error" in text:
                    await self._add_tech("PHP", "Backend Language", source="error_page")
                    count += 1
                if "ASP.NET" in text or "Server Error" in text:
                    await self._add_tech("ASP.NET", "Backend Framework", source="error_page")
                    count += 1
                if "java" in text.lower() or "javax" in text.lower():
                    await self._add_tech("Java", "Backend Language", source="error_page")
                    count += 1
        return count

    async def _run_tech_014(self) -> int:
        """Check for Cloudflare CDN."""
        resp = await self._fetch_target()
        if not resp:
            return 0
        headers = resp.get("headers", {})
        if "cf-ray" in headers or "cf-cache-status" in headers:
            await self._add_tech("Cloudflare", "CDN/WAF", source="cloudflare_headers")
            return 1
        # Check DNS
        cnames = await self.resolve_dns(self.target, "CNAME")
        if any("cloudflare" in c.lower() for c in cnames):
            await self._add_tech("Cloudflare", "CDN/WAF", source="cloudflare_dns")
            return 1
        return 0

    async def _run_tech_015(self) -> int:
        """Identify hosting provider from IP WHOIS/ASN."""
        ips = await self.resolve_dns(self.target)
        if not ips:
            return 0
        # Use ip-api.com for quick lookup
        for ip in ips[:3]:
            data = await self.http_get_json(f"http://ip-api.com/json/{ip}")
            if data and data.get("status") == "success":
                org = data.get("org", "")
                isp = data.get("isp", "")
                await self._add_tech(f"{isp} ({org})", "Hosting Provider",
                                     source="whois_lookup")
                return 1
        return 0

    async def _run_tech_016(self) -> int:
        """BuiltWith API for technology profiling."""
        if not self.keys.builtwith:
            return 0
        data = await self.http_get_json(
            f"https://api.builtwith.com/v21/api.json?KEY={self.keys.builtwith}&LOOKUP={self.target}")
        if data and "Results" in data:
            count = 0
            for result in data["Results"]:
                for path in result.get("Result", {}).get("Paths", []):
                    for tech in path.get("Technologies", []):
                        await self._add_tech(
                            tech.get("Name", ""), tech.get("Tag", ""),
                            source="builtwith")
                        count += 1
            return count
        return 0

    async def _run_tech_017(self) -> int:
        """Check for WAF using wafw00f."""
        result = await self.run_tool(
            "wafw00f", f"wafw00f https://{self.target}", timeout=60)
        if result.success:
            waf_match = re.search(r"is behind\s+(.+)", result.output)
            if waf_match:
                waf_name = waf_match.group(1).strip()
                await self._add_tech(waf_name, "WAF", source="wafw00f")
                return 1
        # Fallback: check common WAF headers
        resp = await self._fetch_target()
        if resp:
            headers = resp.get("headers", {})
            waf_headers = {
                "x-sucuri-id": "Sucuri", "x-sucuri-cache": "Sucuri",
                "cf-ray": "Cloudflare", "x-cdn": "Incapsula",
                "x-iinfo": "Incapsula", "akamai-grn": "Akamai",
                "x-aws-waf": "AWS WAF",
            }
            for h, waf in waf_headers.items():
                if h in headers:
                    await self._add_tech(waf, "WAF", source="waf_header_check")
                    return 1
        return 0

    async def _run_tech_018(self) -> int:
        """Identify CDN provider via CNAME records."""
        cnames = await self.resolve_dns(self.target, "CNAME")
        cdn_map = {
            "cloudfront": "AWS CloudFront", "akamai": "Akamai",
            "fastly": "Fastly", "edgecast": "Edgecast/Verizon",
            "cloudflare": "Cloudflare", "azureedge": "Azure CDN",
            "googleusercontent": "Google CDN", "cdn77": "CDN77",
            "stackpath": "StackPath", "incapdns": "Incapsula",
        }
        for cname in cnames:
            for key, name in cdn_map.items():
                if key in cname.lower():
                    await self._add_tech(name, "CDN", source="cname_cdn")
                    return 1
        return 0

    async def _run_tech_019(self) -> int:
        """Check for CMS version via readme.html, changelog files."""
        version_files = [
            ("/readme.html", "WordPress"), ("/CHANGELOG.txt", "Drupal"),
            ("/CHANGELOG.md", "Various"), ("/wp-includes/version.php", "WordPress"),
            ("/license.txt", "WordPress"),
        ]
        count = 0
        for path, cms in version_files:
            resp = await self._check_path_exists(path)
            if resp:
                self.db.add_finding(self.session_id, Finding(
                    title=f"Version file exposed: {path}",
                    severity=Severity.LOW,
                    url=f"https://{self.target}{path}",
                    source="version_file", check_id="tech_019",
                ))
                count += 1
        return count

    async def _run_tech_020(self) -> int:
        """fingerprintx — service fingerprinting on open ports."""
        result = await self.run_tool(
            "fingerprintx", f"echo {self.target} | fingerprintx", timeout=60)
        if result.success:
            count = 0
            for line in result.lines:
                if ":" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        await self._add_tech(parts[-1], "Service", source="fingerprintx")
                        count += 1
            return count
        return 0

    async def _run_tech_021(self) -> int:
        """Detect API gateway from response headers."""
        resp = await self._fetch_target()
        if not resp:
            return 0
        headers = resp.get("headers", {})
        gw_indicators = {
            "x-amzn-requestid": "AWS API Gateway",
            "x-amzn-trace-id": "AWS",
            "x-request-id": "API Gateway",
            "x-kong-upstream-latency": "Kong",
            "x-ratelimit-limit": "Rate Limited API",
            "apigw-requestid": "AWS API Gateway",
        }
        count = 0
        for h, name in gw_indicators.items():
            if h in headers:
                await self._add_tech(name, "API Gateway", source="api_gw_headers")
                count += 1
        return count

    async def _run_tech_022(self) -> int:
        """Identify GraphQL endpoint via introspection."""
        graphql_paths = ["/graphql", "/api/graphql", "/graphql/v1", "/gql"]
        for path in graphql_paths:
            import httpx
            try:
                async with httpx.AsyncClient(verify=False, timeout=10) as client:
                    resp = await client.post(
                        f"https://{self.target}{path}",
                        json={"query": "{ __schema { types { name } } }"},
                        headers={"Content-Type": "application/json"},
                    )
                    if resp.status_code == 200 and "__schema" in resp.text:
                        await self._add_tech("GraphQL", "API", source="graphql_introspection")
                        self.db.add_finding(self.session_id, Finding(
                            title=f"GraphQL introspection enabled at {path}",
                            severity=Severity.MEDIUM,
                            url=f"https://{self.target}{path}",
                            source="graphql_check", check_id="tech_022",
                        ))
                        return 1
            except Exception:
                pass
        return 0

    async def _run_tech_023(self) -> int:
        """Check for Swagger/OpenAPI documentation."""
        swagger_paths = ["/swagger-ui/", "/swagger-ui.html", "/api-docs",
                         "/api-docs/", "/v2/api-docs", "/v3/api-docs",
                         "/swagger.json", "/openapi.json", "/swagger/"]
        count = 0
        for path in swagger_paths:
            resp = await self._check_path_exists(path, ["swagger", "openapi", "api-docs"])
            if resp:
                self.db.add_endpoint(self.session_id, Endpoint(
                    url=f"https://{self.target}{path}",
                    status_code=resp["status"], is_interesting=True,
                    source="swagger_check", notes="API Documentation",
                ))
                await self._add_tech("Swagger/OpenAPI", "API Documentation", source="swagger_check")
                count += 1
        return count

    async def _run_tech_024(self) -> int:
        """Detect GraphQL Playground or GraphiQL."""
        for path in ["/graphql", "/graphiql", "/playground"]:
            resp = await self._check_path_exists(path, ["graphiql", "playground", "GraphQL"])
            if resp:
                await self._add_tech("GraphQL Playground", "API", source="graphql_playground")
                return 1
        return 0

    async def _run_tech_025(self) -> int:
        """Check for WordPress REST API."""
        resp = await self._check_path_exists("/wp-json/wp/v2/", ["namespace"])
        if resp:
            await self._add_tech("WordPress REST API", "API", source="wp_rest_api")
            return 1
        return 0

    async def _run_tech_026(self) -> int:
        """Identify Laravel via /telescope, /_debugbar, /horizon."""
        laravel_paths = ["/telescope", "/_debugbar", "/horizon",
                         "/telescope/requests", "/horizon/api"]
        for path in laravel_paths:
            resp = await self._check_path_exists(path, ["laravel", "telescope", "horizon"])
            if resp:
                await self._add_tech("Laravel", "Backend Framework", source="laravel_check")
                self.db.add_finding(self.session_id, Finding(
                    title=f"Laravel debug endpoint exposed: {path}",
                    severity=Severity.HIGH,
                    url=f"https://{self.target}{path}",
                    source="laravel_debug", check_id="tech_026",
                ))
                return 1
        return 0

    async def _run_tech_027(self) -> int:
        """Check for Django admin."""
        for path in ["/admin/", "/admin/login/", "/django-admin/"]:
            resp = await self._check_path_exists(path, ["django", "csrfmiddlewaretoken"])
            if resp:
                await self._add_tech("Django", "Backend Framework", source="django_admin")
                return 1
        return 0

    async def _run_tech_028(self) -> int:
        """Detect Rails via cookies and headers."""
        resp = await self._fetch_target()
        if not resp:
            return 0
        headers = resp.get("headers", {})
        cookies = headers.get("set-cookie", "")
        if "_session_id" in cookies or "X-Runtime" in headers:
            await self._add_tech("Ruby on Rails", "Backend Framework", source="rails_detect")
            return 1
        return 0

    async def _run_tech_029(self) -> int:
        """Check for Spring Boot actuator endpoints."""
        actuator_paths = ["/actuator", "/actuator/health", "/actuator/env",
                          "/actuator/info", "/actuator/beans", "/actuator/mappings"]
        count = 0
        for path in actuator_paths:
            resp = await self._check_path_exists(path)
            if resp and resp["status"] == 200:
                await self._add_tech("Spring Boot", "Backend Framework", source="actuator")
                self.db.add_finding(self.session_id, Finding(
                    title=f"Spring Boot Actuator exposed: {path}",
                    severity=Severity.HIGH,
                    url=f"https://{self.target}{path}",
                    source="spring_actuator", check_id="tech_029",
                ))
                count += 1
        return count

    async def _run_tech_030(self) -> int:
        """Identify ASP.NET via viewstate."""
        resp = await self._fetch_target()
        if not resp:
            return 0
        text = resp.get("text", "")
        if "__VIEWSTATE" in text or "__EVENTVALIDATION" in text:
            await self._add_tech("ASP.NET", "Backend Framework", source="viewstate")
            return 1
        return 0

    async def _run_tech_031(self) -> int:
        """Check for PHP via headers and extensions."""
        resp = await self._fetch_target()
        if not resp:
            return 0
        xpb = resp.get("headers", {}).get("x-powered-by", "")
        if "PHP" in xpb.upper():
            ver = re.search(r"PHP/([\d\.]+)", xpb)
            await self._add_tech("PHP", "Backend Language",
                                 version=ver.group(1) if ver else "", source="php_header")
            return 1
        return 0

    async def _run_tech_032(self) -> int:
        """Detect Node.js via Express header."""
        resp = await self._fetch_target()
        if not resp:
            return 0
        xpb = resp.get("headers", {}).get("x-powered-by", "")
        if "express" in xpb.lower():
            await self._add_tech("Express.js (Node.js)", "Backend Framework", source="express_header")
            return 1
        return 0

    async def _run_tech_033(self) -> int:
        """Check for Next.js via __NEXT_DATA__."""
        resp = await self._fetch_target()
        if not resp:
            return 0
        if "__NEXT_DATA__" in resp.get("text", ""):
            await self._add_tech("Next.js", "Frontend Framework", source="nextjs_data")
            return 1
        return 0

    async def _run_tech_034(self) -> int:
        """Check for Nuxt.js via __NUXT__."""
        resp = await self._fetch_target()
        if not resp:
            return 0
        if "__NUXT__" in resp.get("text", ""):
            await self._add_tech("Nuxt.js", "Frontend Framework", source="nuxtjs_data")
            return 1
        return 0

    async def _run_tech_035(self) -> int:
        """Identify Gatsby via gatsby-script."""
        resp = await self._fetch_target()
        if not resp:
            return 0
        text = resp.get("text", "")
        if "gatsby" in text.lower() or "___gatsby" in text:
            await self._add_tech("Gatsby", "Frontend Framework", source="gatsby_detect")
            return 1
        return 0

    async def _run_tech_036(self) -> int:
        """Check for Svelte via class:svelte-xxx."""
        resp = await self._fetch_target()
        if not resp:
            return 0
        if re.search(r'class="svelte-', resp.get("text", "")):
            await self._add_tech("Svelte", "Frontend Framework", source="svelte_detect")
            return 1
        return 0

    async def _run_tech_037(self) -> int:
        """Detect Ember.js."""
        resp = await self._fetch_target()
        if not resp:
            return 0
        text = resp.get("text", "")
        if "ember" in text.lower() and ("ember-cli" in text.lower() or "EmberENV" in text):
            await self._add_tech("Ember.js", "Frontend Framework", source="ember_detect")
            return 1
        return 0

    async def _run_tech_038(self) -> int:
        """Check for Meteor via __meteor_runtime_config__."""
        resp = await self._fetch_target()
        if not resp:
            return 0
        if "__meteor_runtime_config__" in resp.get("text", ""):
            await self._add_tech("Meteor", "Full-Stack Framework", source="meteor_detect")
            return 1
        return 0

    async def _run_tech_039(self) -> int:
        """Identify Flask via Werkzeug headers."""
        resp = await self._fetch_target()
        if not resp:
            return 0
        headers = resp.get("headers", {})
        server = headers.get("server", "")
        if "werkzeug" in server.lower():
            await self._add_tech("Flask (Werkzeug)", "Backend Framework", source="werkzeug")
            return 1
        return 0

    async def _run_tech_040(self) -> int:
        """Detect FastAPI via /docs and /redoc endpoints."""
        for path in ["/docs", "/redoc", "/openapi.json"]:
            resp = await self._check_path_exists(path, ["fastapi", "swagger", "redoc"])
            if resp:
                await self._add_tech("FastAPI", "Backend Framework", source="fastapi_detect")
                return 1
        return 0
