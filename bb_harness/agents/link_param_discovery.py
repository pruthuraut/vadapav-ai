"""
bb_harness.agents.link_param_discovery
Link & Parameter Discovery Agent — 40 checks.
"""
from __future__ import annotations
import re
import json
from typing import List, Set

from bb_harness.agents.base import BaseAgent
from bb_harness.core.models import (
    AgentCategory, Endpoint, Parameter, Finding, Severity,
)


class LinkParamDiscoveryAgent(BaseAgent):
    AGENT_ID = "link_param_discovery"
    CATEGORY = AgentCategory.LINK_PARAM_DISCOVERY
    NAME = "Link & Parameter Discovery"
    DESCRIPTION = "40 checks for extracting links, parameters, APIs, and JS endpoints"

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _fetch_main_page(self) -> dict | None:
        resp = await self.http_get(f"https://{self.target}", timeout=15)
        if not resp or resp["status"] == 0:
            resp = await self.http_get(f"http://{self.target}", timeout=15)
        return resp

    async def _get_js_files(self) -> List[str]:
        """Get all JS file URLs from the main page."""
        resp = await self._fetch_main_page()
        if not resp:
            return []
        js_urls = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', resp["text"])
        result = []
        for url in js_urls:
            if url.startswith("//"):
                url = "https:" + url
            elif url.startswith("/"):
                url = f"https://{self.target}{url}"
            elif not url.startswith("http"):
                url = f"https://{self.target}/{url}"
            result.append(url)
        return result[:50]

    async def _extract_from_js(self, js_text: str) -> dict:
        """Extract endpoints, params, and interesting patterns from JS code."""
        endpoints = set()
        params = set()
        secrets = []

        # API endpoints
        api_patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v[0-9]+/[^"\']+)["\']',
            r'["\'](/graphql[^"\']*)["\']',
            r'["\'](/auth[^"\']*)["\']',
            r'["\'](/user[s]?/[^"\']*)["\']',
            r'["\'](/admin[^"\']*)["\']',
            r'["\'](/login[^"\']*)["\']',
            r'["\'](/register[^"\']*)["\']',
            r'["\'](/upload[^"\']*)["\']',
            r'["\'](/download[^"\']*)["\']',
            r'["\'](/export[^"\']*)["\']',
            r'["\'](/webhook[^"\']*)["\']',
            r'["\'](/search[^"\']*)["\']',
            r'["\'](/callback[^"\']*)["\']',
            r'["\'](/oauth[^"\']*)["\']',
            r'["\'](/saml[^"\']*)["\']',
            r'["\'](/sso[^"\']*)["\']',
        ]
        for pattern in api_patterns:
            matches = re.findall(pattern, js_text, re.I)
            endpoints.update(matches)

        # Full URLs
        full_urls = re.findall(r'(https?://[^\s"\'<>]+)', js_text)
        endpoints.update(full_urls[:50])

        # Parameters
        param_patterns = [
            r'[\?&]([a-zA-Z_][a-zA-Z0-9_]*)=',
            r'params\[?["\']([a-zA-Z_]\w*)',
            r'query["\']?\s*:\s*{[^}]*["\'](\w+)',
            r'body["\']?\s*:\s*{[^}]*["\'](\w+)',
        ]
        for pattern in param_patterns:
            matches = re.findall(pattern, js_text)
            params.update(matches)

        # Secrets / API keys
        secret_patterns = [
            (r'["\']?(api[_-]?key|apikey|api_secret)["\']?\s*[:=]\s*["\']([^"\']+)["\']', "API Key"),
            (r'["\']?(secret[_-]?key|secretkey)["\']?\s*[:=]\s*["\']([^"\']+)["\']', "Secret Key"),
            (r'(AIza[0-9A-Za-z\-_]{35})', "Google API Key"),
            (r'(AKIA[0-9A-Z]{16})', "AWS Access Key"),
            (r'(sk-[a-zA-Z0-9]{48})', "Stripe/OpenAI Key"),
            (r'(ghp_[a-zA-Z0-9]{36})', "GitHub Token"),
        ]
        for pattern, label in secret_patterns:
            matches = re.findall(pattern, js_text, re.I)
            for match in matches:
                val = match[-1] if isinstance(match, tuple) else match
                if len(val) > 5:
                    secrets.append((label, val[:50]))

        return {"endpoints": endpoints, "params": params, "secrets": secrets}

    # ══════════════════════════════════════════════════════════════════════════
    # CHECK IMPLEMENTATIONS
    # ══════════════════════════════════════════════════════════════════════════

    async def _run_link_001(self) -> int:
        """katana — comprehensive web crawling."""
        result = await self.run_tool(
            "katana",
            f"katana -u https://{self.target} -d 3 -silent -jc -kf all",
            timeout=300,
        )
        if result.success:
            count = 0
            for url in result.lines[:500]:
                self.db.add_endpoint(self.session_id, Endpoint(
                    url=url.strip(), source="katana",
                ))
                count += 1
            return count
        return 0

    async def _run_link_002(self) -> int:
        """hakrawler — fast web crawling with depth control."""
        result = await self.run_tool(
            "hakrawler",
            f"echo https://{self.target} | hakrawler -d 3 -subs",
            timeout=180,
        )
        if result.success:
            count = 0
            for url in result.lines[:500]:
                self.db.add_endpoint(self.session_id, Endpoint(
                    url=url.strip(), source="hakrawler",
                ))
                count += 1
            return count
        return 0

    async def _run_link_003(self) -> int:
        """Burp Suite spider (informational — manual tool)."""
        # Can't automate Burp, but log it as manual check
        return 0

    async def _run_link_004(self) -> int:
        """LinkFinder — extract links from JS files."""
        js_files = await self._get_js_files()
        count = 0
        for js_url in js_files[:20]:
            # Try LinkFinder CLI
            result = await self.run_tool(
                "linkfinder",
                f"linkfinder -i {js_url} -o cli",
                timeout=30,
            )
            if result.success:
                for line in result.lines:
                    self.db.add_endpoint(self.session_id, Endpoint(
                        url=line.strip(), source="linkfinder",
                    ))
                    count += 1
            else:
                # Fallback: regex extraction
                resp = await self.http_get(js_url, timeout=10)
                if resp and resp["status"] == 200:
                    data = await self._extract_from_js(resp["text"])
                    for ep in data["endpoints"]:
                        if ep.startswith("/"):
                            ep = f"https://{self.target}{ep}"
                        self.db.add_endpoint(self.session_id, Endpoint(
                            url=ep, source="js_regex_extract",
                        ))
                        count += 1
        return count

    async def _run_link_005(self) -> int:
        """JSParser — extract API endpoints from JS files."""
        js_files = await self._get_js_files()
        count = 0
        for js_url in js_files[:20]:
            resp = await self.http_get(js_url, timeout=10)
            if resp and resp["status"] == 200:
                data = await self._extract_from_js(resp["text"])
                for ep in data["endpoints"]:
                    if ep.startswith("/"):
                        full_url = f"https://{self.target}{ep}"
                    else:
                        full_url = ep
                    self.db.add_endpoint(self.session_id, Endpoint(
                        url=full_url, source="js_parser", is_interesting=True,
                    ))
                    count += 1
        return count

    async def _run_link_006(self) -> int:
        """paramspider — parameter discovery from historical data."""
        result = await self.run_tool(
            "paramspider",
            f"paramspider -d {self.target} --exclude png,jpg,gif,css,svg",
            timeout=120,
        )
        if result.success:
            count = 0
            for line in result.lines:
                if "?" in line:
                    url = line.strip()
                    params_str = url.split("?", 1)[1] if "?" in url else ""
                    for p in params_str.split("&"):
                        name = p.split("=")[0]
                        if name:
                            self.db.add_parameter(self.session_id, Parameter(
                                url=url, name=name, source="paramspider",
                            ))
                            count += 1
            return count
        # Fallback: extract params from wayback URLs
        resp = await self.http_get(
            f"https://web.archive.org/cdx/search/cdx?url={self.target}/*&output=text&fl=original&collapse=urlkey&filter=mimetype:text/html&limit=500",
            timeout=30,
        )
        if resp and resp["status"] == 200:
            count = 0
            for line in resp["text"].splitlines():
                url = line.strip()
                if "?" in url:
                    params_str = url.split("?", 1)[1]
                    for p in params_str.split("&"):
                        name = p.split("=")[0]
                        if name:
                            self.db.add_parameter(self.session_id, Parameter(
                                url=url, name=name, source="wayback_params",
                            ))
                            count += 1
            return count
        return 0

    async def _run_link_007(self) -> int:
        """arjun — HTTP parameter discovery."""
        result = await self.run_tool(
            "arjun",
            f"arjun -u https://{self.target}/ -t 10 -oT /dev/stdout",
            timeout=180,
        )
        if result.success:
            count = 0
            for line in result.lines:
                m = re.search(r"Found:\s*(\S+)", line)
                if m:
                    self.db.add_parameter(self.session_id, Parameter(
                        url=f"https://{self.target}/", name=m.group(1), source="arjun",
                    ))
                    count += 1
            return count
        return 0

    async def _run_link_008(self) -> int:
        """Check for path-based parameters in URL paths."""
        endpoints = self.db.get_endpoints(self.session_id)
        count = 0
        path_param_pattern = re.compile(r'/(\d+)(?:/|$)|/([0-9a-f-]{36})(?:/|$)', re.I)
        for ep in endpoints[:200]:
            url = ep.get("url", "")
            matches = path_param_pattern.findall(url)
            if matches:
                self.db.add_parameter(self.session_id, Parameter(
                    url=url, name="path_id", param_type="path",
                    source="path_param_analysis",
                ))
                count += 1
        return count

    async def _run_link_009(self) -> int:
        """Analyze JavaScript for API routes and hidden parameters."""
        js_files = await self._get_js_files()
        total_params = 0
        total_secrets = 0
        for js_url in js_files[:15]:
            resp = await self.http_get(js_url, timeout=10)
            if resp and resp["status"] == 200:
                data = await self._extract_from_js(resp["text"])
                for param in data["params"]:
                    self.db.add_parameter(self.session_id, Parameter(
                        url=js_url, name=param, source="js_analysis",
                    ))
                    total_params += 1
                for label, val in data["secrets"]:
                    self.db.add_finding(self.session_id, Finding(
                        title=f"{label} found in JS: {val[:30]}...",
                        severity=Severity.HIGH,
                        url=js_url,
                        evidence=val,
                        source="js_secret_scan", check_id="link_009",
                    ))
                    total_secrets += 1
        return total_params + total_secrets

    async def _run_link_010(self) -> int:
        """Check for URL fragments and hash-based routing."""
        resp = await self._fetch_main_page()
        if not resp:
            return 0
        text = resp["text"]
        hash_routes = re.findall(r'href=["\']#(/[^"\']+)["\']', text)
        hash_routes += re.findall(r'path:\s*["\']([^"\']+)["\']', text)
        count = 0
        for route in set(hash_routes):
            self.db.add_endpoint(self.session_id, Endpoint(
                url=f"https://{self.target}/#{route}",
                source="hash_routing", is_interesting=True,
            ))
            count += 1
        return count

    async def _run_link_011(self) -> int:
        """Discover WebSocket endpoints."""
        resp = await self._fetch_main_page()
        if not resp:
            return 0
        text = resp["text"]
        ws_patterns = re.findall(r'(wss?://[^\s"\'<>]+)', text)
        # Also check JS files
        js_files = await self._get_js_files()
        for js_url in js_files[:10]:
            js_resp = await self.http_get(js_url, timeout=10)
            if js_resp and js_resp["status"] == 200:
                ws_patterns += re.findall(r'(wss?://[^\s"\'<>]+)', js_resp["text"])
        count = 0
        for ws in set(ws_patterns):
            self.db.add_endpoint(self.session_id, Endpoint(
                url=ws, source="websocket_discovery", is_interesting=True,
                notes="WebSocket endpoint",
            ))
            count += 1
        return count

    async def _run_link_012(self) -> int:
        """Look for SSE endpoints."""
        resp = await self._fetch_main_page()
        if not resp:
            return 0
        text = resp["text"]
        sse_patterns = re.findall(r'EventSource\(["\']([^"\']+)["\']', text)
        count = 0
        for sse in set(sse_patterns):
            url = sse if sse.startswith("http") else f"https://{self.target}{sse}"
            self.db.add_endpoint(self.session_id, Endpoint(
                url=url, source="sse_discovery", is_interesting=True,
                notes="Server-Sent Events endpoint",
            ))
            count += 1
        return count

    async def _run_link_013(self) -> int:
        """Find polling endpoints."""
        resp = await self._fetch_main_page()
        if not resp:
            return 0
        text = resp["text"]
        polling = re.findall(r'(?:setInterval|setTimeout)\s*\([^,]*fetch\(["\']([^"\']+)', text)
        polling += re.findall(r'\.poll\(["\']([^"\']+)', text)
        count = 0
        for url in set(polling):
            if not url.startswith("http"):
                url = f"https://{self.target}{url}"
            self.db.add_endpoint(self.session_id, Endpoint(
                url=url, source="polling_discovery", is_interesting=True,
                notes="Polling/long-polling endpoint",
            ))
            count += 1
        return count

    async def _run_link_014(self) -> int:
        """Check for microservices architecture with multiple API gateways."""
        api_prefixes = ["/api/", "/v1/", "/v2/", "/v3/",
                        "/gateway/", "/service/", "/proxy/"]
        count = 0
        for prefix in api_prefixes:
            resp = await self.http_get(f"https://{self.target}{prefix}", timeout=8)
            if resp and resp["status"] in range(200, 500):
                self.db.add_endpoint(self.session_id, Endpoint(
                    url=f"https://{self.target}{prefix}",
                    status_code=resp["status"],
                    source="microservice_check", is_interesting=True,
                ))
                count += 1
        return count

    async def _run_link_015(self) -> int:
        """Discover internal API docs in JS source map files."""
        js_files = await self._get_js_files()
        count = 0
        for js_url in js_files[:20]:
            map_url = js_url + ".map"
            resp = await self.http_get(map_url, timeout=10)
            if resp and resp["status"] == 200:
                self.db.add_finding(self.session_id, Finding(
                    title=f"JS Source Map exposed: {map_url}",
                    severity=Severity.HIGH,
                    url=map_url,
                    source="sourcemap_check", check_id="link_015",
                ))
                # Extract sources from sourcemap
                try:
                    data = json.loads(resp["text"])
                    for source in data.get("sources", []):
                        self.db.add_endpoint(self.session_id, Endpoint(
                            url=source, source="sourcemap",
                        ))
                        count += 1
                except Exception:
                    pass
                count += 1
        return count

    async def _run_link_016(self) -> int:
        """Extract variables and constants from minified JavaScript."""
        js_files = await self._get_js_files()
        count = 0
        for js_url in js_files[:10]:
            resp = await self.http_get(js_url, timeout=10)
            if resp and resp["status"] == 200:
                # Extract const/var assignments that look like config
                configs = re.findall(
                    r'(?:const|var|let)\s+([A-Z_]{3,})\s*=\s*["\']([^"\']+)["\']',
                    resp["text"])
                for name, value in configs:
                    self.db.add_parameter(self.session_id, Parameter(
                        url=js_url, name=name, param_type="constant",
                        sample_value=value[:50], source="js_constants",
                    ))
                    count += 1
        return count

    async def _run_link_017(self) -> int:
        """Check for sourcemap files (.map)."""
        # Already covered in link_015, but we also check for inline sourcemaps
        resp = await self._fetch_main_page()
        if not resp:
            return 0
        text = resp["text"]
        map_refs = re.findall(r'sourceMappingURL=(\S+\.map)', text)
        count = 0
        for ref in set(map_refs):
            url = ref if ref.startswith("http") else f"https://{self.target}/{ref}"
            check = await self.http_get(url, timeout=10)
            if check and check["status"] == 200:
                self.db.add_finding(self.session_id, Finding(
                    title=f"Source map accessible: {ref}",
                    severity=Severity.MEDIUM,
                    url=url,
                    source="sourcemap_inline", check_id="link_017",
                ))
                count += 1
        return count

    async def _run_link_018(self) -> int:
        """Analyze compiled templates for route definitions."""
        resp = await self._fetch_main_page()
        if not resp:
            return 0
        text = resp["text"]
        route_patterns = [
            r'path:\s*["\']([^"\']+)["\']',
            r'route:\s*["\']([^"\']+)["\']',
            r'component:\s*["\']([^"\']+)["\']',
            r'to:\s*["\']([^"\']+)["\']',
            r'href:\s*["\']([^"\']+)["\']',
        ]
        routes = set()
        for pattern in route_patterns:
            routes.update(re.findall(pattern, text))
        count = 0
        for route in routes:
            if route.startswith("/"):
                self.db.add_endpoint(self.session_id, Endpoint(
                    url=f"https://{self.target}{route}",
                    source="template_routes", is_interesting=True,
                ))
                count += 1
        return count

    async def _run_link_019(self) -> int:
        """Check for REST API versioning."""
        count = 0
        for v in ["v1", "v2", "v3", "v4"]:
            for prefix in ["/api/", "/"]:
                path = f"{prefix}{v}/"
                resp = await self.http_get(f"https://{self.target}{path}", timeout=8)
                if resp and resp["status"] in range(200, 404):
                    self.db.add_endpoint(self.session_id, Endpoint(
                        url=f"https://{self.target}{path}",
                        status_code=resp["status"],
                        source="api_versioning",
                    ))
                    count += 1
        return count

    async def _run_link_020(self) -> int:
        """Look for GraphQL schema via introspection."""
        import httpx
        paths = ["/graphql", "/api/graphql", "/graphql/v1", "/gql", "/query"]
        for path in paths:
            try:
                async with httpx.AsyncClient(verify=False, timeout=10) as client:
                    resp = await client.post(
                        f"https://{self.target}{path}",
                        json={"query": "{ __schema { queryType { name } mutationType { name } types { name kind } } }"},
                        headers={"Content-Type": "application/json"},
                    )
                    if resp.status_code == 200 and "__schema" in resp.text:
                        data = resp.json()
                        types = data.get("data", {}).get("__schema", {}).get("types", [])
                        self.db.add_finding(self.session_id, Finding(
                            title=f"GraphQL schema introspection at {path}",
                            severity=Severity.MEDIUM,
                            url=f"https://{self.target}{path}",
                            description=f"Found {len(types)} types",
                            source="graphql_introspection", check_id="link_020",
                        ))
                        return 1
            except Exception:
                pass
        return 0

    async def _run_link_021(self) -> int:
        """Discover SOAP WSDL endpoints."""
        wsdl_paths = ["/?wsdl", "/?WSDL", "/service?wsdl", "/ws?wsdl",
                       "/api?wsdl", "/webservice?wsdl", "/?xsd"]
        count = 0
        for path in wsdl_paths:
            resp = await self.http_get(f"https://{self.target}{path}", timeout=8)
            if resp and resp["status"] == 200 and "wsdl" in resp.get("text", "").lower():
                self.db.add_endpoint(self.session_id, Endpoint(
                    url=f"https://{self.target}{path}",
                    source="wsdl_discovery", is_interesting=True,
                    notes="SOAP WSDL endpoint",
                ))
                count += 1
        return count

    async def _run_link_022(self) -> int:
        """Check for XML-RPC endpoints."""
        resp = await self.http_get(f"https://{self.target}/xmlrpc.php", timeout=10)
        if resp and resp["status"] == 200 and "xml" in resp.get("text", "").lower():
            self.db.add_finding(self.session_id, Finding(
                title="XML-RPC endpoint found",
                severity=Severity.MEDIUM,
                url=f"https://{self.target}/xmlrpc.php",
                source="xmlrpc_check", check_id="link_022",
            ))
            return 1
        return 0

    async def _run_link_023(self) -> int:
        """Find form action URLs and hidden form fields."""
        resp = await self._fetch_main_page()
        if not resp:
            return 0
        text = resp["text"]
        forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\']', text, re.I)
        hidden = re.findall(r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\']', text, re.I)
        count = 0
        for form in forms:
            url = form if form.startswith("http") else f"https://{self.target}{form}"
            self.db.add_endpoint(self.session_id, Endpoint(
                url=url, method="POST", source="form_action",
            ))
            count += 1
        for name in hidden:
            self.db.add_parameter(self.session_id, Parameter(
                url=f"https://{self.target}", name=name,
                param_type="hidden_field", source="hidden_form_field",
            ))
            count += 1
        return count

    async def _run_link_024(self) -> int:
        """Analyze AJAX calls (extract from JS source)."""
        js_files = await self._get_js_files()
        count = 0
        for js_url in js_files[:15]:
            resp = await self.http_get(js_url, timeout=10)
            if resp and resp["status"] == 200:
                ajax_patterns = re.findall(
                    r'(?:fetch|axios|\.get|\.post|\.put|\.delete|XMLHttpRequest)\s*\(\s*["\']([^"\']+)["\']',
                    resp["text"], re.I)
                for url in set(ajax_patterns):
                    if url.startswith("/"):
                        url = f"https://{self.target}{url}"
                    self.db.add_endpoint(self.session_id, Endpoint(
                        url=url, source="ajax_analysis", is_interesting=True,
                    ))
                    count += 1
        return count

    async def _run_link_025(self) -> int:
        """Check for iframe and embed source URLs."""
        resp = await self._fetch_main_page()
        if not resp:
            return 0
        text = resp["text"]
        iframes = re.findall(r'<iframe[^>]*src=["\']([^"\']+)["\']', text, re.I)
        embeds = re.findall(r'<embed[^>]*src=["\']([^"\']+)["\']', text, re.I)
        count = 0
        for url in set(iframes + embeds):
            self.db.add_endpoint(self.session_id, Endpoint(
                url=url, source="iframe_embed", notes="Embedded content",
            ))
            count += 1
        return count

    async def _run_link_026(self) -> int:
        """Discover image/asset CDN URLs."""
        resp = await self._fetch_main_page()
        if not resp:
            return 0
        text = resp["text"]
        cdn_urls = set()
        for attr in ["src", "href", "data-src"]:
            matches = re.findall(rf'{attr}=["\']([^"\']+)["\']', text)
            for url in matches:
                if any(cdn in url.lower() for cdn in
                       ["cdn", "cloudfront", "cloudflare", "akamai", "fastly",
                        "s3.amazonaws", "storage.googleapis", "azureedge"]):
                    cdn_urls.add(url)
        count = 0
        for url in cdn_urls:
            self.db.add_endpoint(self.session_id, Endpoint(
                url=url, source="cdn_assets", notes="CDN asset",
            ))
            count += 1
        return count

    async def _run_link_027(self) -> int:
        """Look for OAuth/OpenID endpoints."""
        resp = await self.http_get(
            f"https://{self.target}/.well-known/openid-configuration", timeout=10)
        if resp and resp["status"] == 200:
            try:
                data = json.loads(resp["text"])
                count = 0
                for key in ["authorization_endpoint", "token_endpoint",
                            "userinfo_endpoint", "jwks_uri", "revocation_endpoint"]:
                    if key in data:
                        self.db.add_endpoint(self.session_id, Endpoint(
                            url=data[key], source="openid_config", is_interesting=True,
                        ))
                        count += 1
                return count
            except Exception:
                pass
        return 0

    async def _run_link_028(self) -> int:
        """Check for SAML metadata endpoints."""
        saml_paths = ["/saml/metadata", "/saml2/metadata",
                      "/federationmetadata/2007-06/federationmetadata.xml",
                      "/auth/saml/metadata"]
        count = 0
        for path in saml_paths:
            resp = await self.http_get(f"https://{self.target}{path}", timeout=8)
            if resp and resp["status"] == 200 and "saml" in resp.get("text", "").lower():
                self.db.add_endpoint(self.session_id, Endpoint(
                    url=f"https://{self.target}{path}",
                    source="saml_metadata", is_interesting=True,
                    notes="SAML metadata",
                ))
                count += 1
        return count

    async def _run_link_029(self) -> int:
        """Find callback/redirect URLs in auth flows."""
        resp = await self._fetch_main_page()
        if not resp:
            return 0
        text = resp["text"]
        redirects = re.findall(r'(?:redirect_uri|callback|return_url|next|returnTo)\s*[=:]\s*["\']?([^\s"\'&]+)', text, re.I)
        count = 0
        for url in set(redirects):
            self.db.add_parameter(self.session_id, Parameter(
                url=f"https://{self.target}", name="redirect_uri",
                sample_value=url[:100], source="auth_redirect",
            ))
            count += 1
        return count

    async def _run_link_030(self) -> int:
        """Analyze postMessage handlers."""
        resp = await self._fetch_main_page()
        if not resp:
            return 0
        text = resp["text"]
        pm_handlers = re.findall(r'addEventListener\s*\(\s*["\']message["\']', text)
        if pm_handlers:
            self.db.add_finding(self.session_id, Finding(
                title=f"postMessage handler found on {self.target}",
                severity=Severity.LOW,
                description=f"Found {len(pm_handlers)} message event listeners",
                source="postmessage_check", check_id="link_030",
            ))
            return len(pm_handlers)
        return 0

    async def _run_link_031(self) -> int:
        """Check for URL parameters in Referer headers."""
        # This is more of a manual/proxy check, but we can check outgoing links
        resp = await self._fetch_main_page()
        if not resp:
            return 0
        links = re.findall(r'href=["\']([^"\']+)["\']', resp["text"])
        external = [l for l in links if l.startswith("http") and self.target not in l]
        if external:
            self.db.add_finding(self.session_id, Finding(
                title=f"External links found ({len(external)} outgoing)",
                severity=Severity.INFO,
                description=f"First 5: {', '.join(external[:5])}",
                source="referer_check", check_id="link_031",
            ))
            return len(external)
        return 0

    async def _run_link_032(self) -> int:
        """Look for email templates with parameterized URLs."""
        # Search for email-related endpoints
        paths = ["/unsubscribe", "/email/preferences", "/newsletter",
                 "/verify-email", "/reset-password", "/confirm"]
        count = 0
        for path in paths:
            resp = await self.http_get(f"https://{self.target}{path}", timeout=8)
            if resp and resp["status"] in range(200, 404):
                self.db.add_endpoint(self.session_id, Endpoint(
                    url=f"https://{self.target}{path}",
                    status_code=resp["status"],
                    source="email_endpoints",
                ))
                count += 1
        return count

    async def _run_link_033(self) -> int:
        """Check for webhooks with configurable callback URLs."""
        webhook_paths = ["/webhook", "/webhooks", "/api/webhooks",
                         "/hook", "/hooks", "/callback"]
        count = 0
        for path in webhook_paths:
            resp = await self.http_get(f"https://{self.target}{path}", timeout=8)
            if resp and resp["status"] in [200, 401, 403, 405]:
                self.db.add_endpoint(self.session_id, Endpoint(
                    url=f"https://{self.target}{path}",
                    status_code=resp["status"],
                    source="webhook_check", is_interesting=True,
                    notes="Webhook endpoint",
                ))
                count += 1
        return count

    async def _run_link_034(self) -> int:
        """Discover file upload endpoints."""
        upload_paths = ["/upload", "/api/upload", "/file/upload",
                        "/media/upload", "/import", "/api/import"]
        count = 0
        for path in upload_paths:
            resp = await self.http_get(f"https://{self.target}{path}", timeout=8)
            if resp and resp["status"] in [200, 401, 403, 405]:
                self.db.add_endpoint(self.session_id, Endpoint(
                    url=f"https://{self.target}{path}",
                    status_code=resp["status"],
                    source="upload_check", is_interesting=True,
                ))
                count += 1
        return count

    async def _run_link_035(self) -> int:
        """Check for export/download endpoints."""
        export_paths = ["/export", "/download", "/api/export",
                        "/api/download", "/report/download", "/data/export"]
        count = 0
        for path in export_paths:
            resp = await self.http_get(f"https://{self.target}{path}", timeout=8)
            if resp and resp["status"] in [200, 401, 403, 302]:
                self.db.add_endpoint(self.session_id, Endpoint(
                    url=f"https://{self.target}{path}",
                    status_code=resp["status"],
                    source="export_check", is_interesting=True,
                ))
                count += 1
        return count

    async def _run_link_036(self) -> int:
        """Look for search endpoints."""
        search_paths = ["/search", "/api/search", "/find", "/query",
                        "/lookup", "/autocomplete", "/suggest"]
        count = 0
        for path in search_paths:
            resp = await self.http_get(f"https://{self.target}{path}?q=test", timeout=8)
            if resp and resp["status"] in [200, 401, 403]:
                self.db.add_endpoint(self.session_id, Endpoint(
                    url=f"https://{self.target}{path}",
                    status_code=resp["status"],
                    source="search_endpoint",
                ))
                self.db.add_parameter(self.session_id, Parameter(
                    url=f"https://{self.target}{path}", name="q",
                    source="search_param",
                ))
                count += 1
        return count

    async def _run_link_037(self) -> int:
        """Check for pagination parameters."""
        endpoints = self.db.get_endpoints(self.session_id)
        count = 0
        for ep in endpoints[:50]:
            url = ep.get("url", "")
            if any(p in url.lower() for p in ["page=", "offset=", "limit=", "cursor="]):
                for param in ["page", "offset", "limit", "cursor", "per_page", "size"]:
                    if param in url.lower():
                        self.db.add_parameter(self.session_id, Parameter(
                            url=url, name=param, source="pagination_analysis",
                        ))
                        count += 1
        return count

    async def _run_link_038(self) -> int:
        """Discover batch/bulk operation endpoints."""
        batch_paths = ["/batch", "/bulk", "/api/batch", "/api/bulk",
                       "/mass", "/multi", "/api/multi"]
        count = 0
        for path in batch_paths:
            resp = await self.http_get(f"https://{self.target}{path}", timeout=8)
            if resp and resp["status"] in [200, 401, 403, 405]:
                self.db.add_endpoint(self.session_id, Endpoint(
                    url=f"https://{self.target}{path}",
                    status_code=resp["status"],
                    source="batch_endpoint", is_interesting=True,
                ))
                count += 1
        return count

    async def _run_link_039(self) -> int:
        """Check for admin/debug endpoints from JS route definitions."""
        js_files = await self._get_js_files()
        count = 0
        admin_patterns = [
            r'["\']/(admin[^"\']*)["\']',
            r'["\']/(debug[^"\']*)["\']',
            r'["\']/(internal[^"\']*)["\']',
            r'["\']/(management[^"\']*)["\']',
            r'["\']/(superadmin[^"\']*)["\']',
        ]
        for js_url in js_files[:10]:
            resp = await self.http_get(js_url, timeout=10)
            if resp and resp["status"] == 200:
                for pattern in admin_patterns:
                    matches = re.findall(pattern, resp["text"], re.I)
                    for m in matches:
                        self.db.add_endpoint(self.session_id, Endpoint(
                            url=f"https://{self.target}/{m}",
                            source="js_admin_routes", is_interesting=True,
                        ))
                        count += 1
        return count

    async def _run_link_040(self) -> int:
        """Look for WebSocket message format from JS analysis."""
        js_files = await self._get_js_files()
        count = 0
        for js_url in js_files[:10]:
            resp = await self.http_get(js_url, timeout=10)
            if resp and resp["status"] == 200:
                # Look for WebSocket send patterns
                ws_sends = re.findall(
                    r'\.send\s*\(\s*(?:JSON\.stringify\s*\()?\s*\{([^}]+)\}',
                    resp["text"])
                for send in ws_sends:
                    keys = re.findall(r'["\']?(\w+)["\']?\s*:', send)
                    for key in keys:
                        self.db.add_parameter(self.session_id, Parameter(
                            url=js_url, name=key, param_type="websocket",
                            source="ws_message_format",
                        ))
                        count += 1
        return count
