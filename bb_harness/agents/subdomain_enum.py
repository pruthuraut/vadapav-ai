"""
bb_harness.agents.subdomain_enum
Subdomain Enumeration Agent — 50 checks for discovering subdomains.
Implements both CLI-tool wrappers and pure-Python API fallbacks.
"""
from __future__ import annotations
import re
import json
import asyncio
from typing import List, Optional
from urllib.parse import quote

from bb_harness.agents.base import BaseAgent
from bb_harness.core.models import (
    AgentCategory, Subdomain, Finding, Severity, Technology
)


class SubdomainEnumAgent(BaseAgent):
    AGENT_ID = "subdomain_enum"
    CATEGORY = AgentCategory.SUBDOMAIN_ENUM
    NAME = "Subdomain Enumeration"
    DESCRIPTION = "50 checks for passive & active subdomain discovery"

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _extract_subdomains_from_text(self, text: str) -> List[str]:
        """Extract valid subdomains from arbitrary text for the current target."""
        domain = self.target.replace(".", r"\.")
        pattern = rf"[\w\.\-]+\.{domain}"
        matches = re.findall(pattern, text, re.IGNORECASE)
        # Deduplicate and clean
        seen = set()
        results = []
        for m in matches:
            m = m.strip(".").lower()
            if m not in seen and m != self.target:
                seen.add(m)
                results.append(m)
        return results

    async def _store_subdomains(self, subdomains: List[str], source: str) -> int:
        """Store discovered subdomains in the database."""
        count = 0
        for s in subdomains:
            sub = Subdomain(subdomain=s, domain=self.target, source=source)
            if self.db.add_subdomain(self.session_id, sub):
                count += 1
        return count

    # ══════════════════════════════════════════════════════════════════════════
    # CHECK IMPLEMENTATIONS
    # ══════════════════════════════════════════════════════════════════════════

    async def _run_sub_001(self) -> int:
        """subfinder — passive subdomain enumeration."""
        result = await self.run_tool(
            "subfinder",
            f"subfinder -d {self.target} -silent -all",
        )
        if result.success:
            subs = [l for l in result.lines if l.endswith(self.target)]
            return await self._store_subdomains(subs, "subfinder")
        return 0

    async def _run_sub_002(self) -> int:
        """amass — deep subdomain discovery with OSINT."""
        result = await self.run_tool(
            "amass",
            f"amass enum -passive -d {self.target}",
            timeout=600,
        )
        if result.success:
            subs = self._extract_subdomains_from_text(result.output)
            return await self._store_subdomains(subs, "amass")
        return 0

    async def _run_sub_003(self) -> int:
        """assetfinder — find subdomains from various data sources."""
        result = await self.run_tool(
            "assetfinder",
            f"assetfinder --subs-only {self.target}",
        )
        if result.success:
            subs = [l for l in result.lines if l.endswith(self.target)]
            return await self._store_subdomains(subs, "assetfinder")
        return 0

    async def _run_sub_004(self) -> int:
        """Findomain — fast subdomain enumeration with CT."""
        result = await self.run_tool(
            "findomain",
            f"findomain -t {self.target} -q",
        )
        if result.success:
            subs = [l for l in result.lines if l.endswith(self.target)]
            return await self._store_subdomains(subs, "findomain")
        return 0

    async def _run_sub_005(self) -> int:
        """knockpy — subdomain enumeration with DNS zone transfer checks."""
        result = await self.run_tool(
            "knockpy",
            f"knockpy {self.target}",
            timeout=600,
        )
        if result.success:
            subs = self._extract_subdomains_from_text(result.output)
            return await self._store_subdomains(subs, "knockpy")
        return 0

    async def _run_sub_006(self) -> int:
        """DNSdumpster — DNS recon and visual subdomain mapping (API)."""
        data = await self.http_get_json(
            f"https://api.hackertarget.com/hostsearch/?q={self.target}"
        )
        if data and isinstance(data, str):
            subs = []
            for line in data.strip().splitlines():
                parts = line.split(",")
                if parts and parts[0].endswith(self.target):
                    subs.append(parts[0])
            return await self._store_subdomains(subs, "dnsdumpster/hackertarget")
        return 0

    async def _run_sub_007(self) -> int:
        """crt.sh — certificate transparency logs (pure Python)."""
        data = await self.http_get_json(
            f"https://crt.sh/?q=%25.{self.target}&output=json"
        )
        if data and isinstance(data, list):
            subs = set()
            for entry in data:
                name = entry.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lstrip("*.")
                    if n.endswith(self.target):
                        subs.add(n)
            return await self._store_subdomains(list(subs), "crt.sh")
        return 0

    async def _run_sub_008(self) -> int:
        """SecurityTrails API — historical and current DNS records."""
        if not self.keys.securitytrails:
            return 0
        data = await self.http_get_json(
            f"https://api.securitytrails.com/v1/domain/{self.target}/subdomains",
            headers={"APIKEY": self.keys.securitytrails},
        )
        if data and "subdomains" in data:
            subs = [f"{s}.{self.target}" for s in data["subdomains"]]
            return await self._store_subdomains(subs, "securitytrails")
        return 0

    async def _run_sub_009(self) -> int:
        """Wayback Machine CDX API — discovering old subdomains."""
        data = await self.http_get(
            f"https://web.archive.org/cdx/search/cdx?url=*.{self.target}/*&output=text&fl=original&collapse=urlkey",
            timeout=60,
        )
        if data and data["status"] == 200:
            subs = set()
            for line in data["text"].splitlines():
                try:
                    from urllib.parse import urlparse
                    host = urlparse(line.strip()).hostname
                    if host and host.endswith(self.target):
                        subs.add(host)
                except Exception:
                    pass
            return await self._store_subdomains(list(subs), "wayback")
        return 0

    async def _run_sub_010(self) -> int:
        """VirusTotal — subdomain enumeration from passive DNS."""
        if not self.keys.virustotal:
            return 0
        data = await self.http_get_json(
            f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={self.keys.virustotal}&domain={self.target}"
        )
        if data and "subdomains" in data:
            return await self._store_subdomains(data["subdomains"], "virustotal")
        return 0

    async def _run_sub_011(self) -> int:
        """Shodan — subdomain and open port discovery."""
        if not self.keys.shodan:
            return 0
        data = await self.http_get_json(
            f"https://api.shodan.io/dns/domain/{self.target}?key={self.keys.shodan}"
        )
        if data and "subdomains" in data:
            subs = [f"{s}.{self.target}" for s in data["subdomains"]]
            return await self._store_subdomains(subs, "shodan")
        return 0

    async def _run_sub_012(self) -> int:
        """Censys — certificate-based subdomain discovery."""
        if not self.keys.censys_id or not self.keys.censys_secret:
            return 0
        import base64
        auth = base64.b64encode(
            f"{self.keys.censys_id}:{self.keys.censys_secret}".encode()
        ).decode()
        data = await self.http_get_json(
            f"https://search.censys.io/api/v2/certificates/search?q={self.target}&per_page=100",
            headers={"Authorization": f"Basic {auth}"},
        )
        if data and "result" in data:
            subs = set()
            for hit in data["result"].get("hits", []):
                for name in hit.get("names", []):
                    if name.endswith(self.target):
                        subs.add(name.lstrip("*."))
            return await self._store_subdomains(list(subs), "censys")
        return 0

    async def _run_sub_013(self) -> int:
        """Facebook CT logs — certificate transparency search."""
        data = await self.http_get_json(
            f"https://graph.facebook.com/certificates?query={self.target}&fields=domains&limit=1000&access_token=|"
        )
        if data and "data" in data:
            subs = set()
            for entry in data["data"]:
                for d in entry.get("domains", []):
                    if d.endswith(self.target):
                        subs.add(d.lstrip("*."))
            return await self._store_subdomains(list(subs), "facebook_ct")
        return 0

    async def _run_sub_014(self) -> int:
        """Google dorking: site:target.com -www (pure Python scrape simulation)."""
        # Use a public search API proxy as a fallback
        data = await self.http_get(
            f"https://www.google.com/search?q=site:{self.target}+-www.{self.target}&num=100",
        )
        if data and data["status"] == 200:
            subs = self._extract_subdomains_from_text(data["text"])
            return await self._store_subdomains(subs, "google_dork")
        return 0

    async def _run_sub_015(self) -> int:
        """Bing dorking: site:target.com."""
        data = await self.http_get(
            f"https://www.bing.com/search?q=site:{self.target}&count=50",
        )
        if data and data["status"] == 200:
            subs = self._extract_subdomains_from_text(data["text"])
            return await self._store_subdomains(subs, "bing_dork")
        return 0

    async def _run_sub_016(self) -> int:
        """Yahoo and DuckDuckGo subdomain diversity."""
        subs = set()
        for url in [
            f"https://html.duckduckgo.com/html/?q=site:{self.target}",
            f"https://search.yahoo.com/search?p=site:{self.target}&n=50",
        ]:
            data = await self.http_get(url)
            if data and data["status"] == 200:
                subs.update(self._extract_subdomains_from_text(data["text"]))
        return await self._store_subdomains(list(subs), "search_engines")

    async def _run_sub_017(self) -> int:
        """DNS brute force with dnsrecon."""
        result = await self.run_tool(
            "dnsrecon",
            f"dnsrecon -d {self.target} -t brt --lifetime 3",
            timeout=600,
        )
        if result.success:
            subs = self._extract_subdomains_from_text(result.output)
            return await self._store_subdomains(subs, "dnsrecon_brute")
        return 0

    async def _run_sub_018(self) -> int:
        """massdns — fast DNS resolution of discovered subdomains."""
        # Get existing subdomains from DB for resolution
        existing = self.db.get_subdomains(self.session_id)
        if not existing:
            return 0
        result = await self.run_tool(
            "massdns",
            f"echo {' '.join(s['subdomain'] for s in existing[:500])} | tr ' ' '\\n' | massdns -r /usr/share/massdns/lists/resolvers.txt -t A -o S",
            timeout=300,
        )
        if result.success:
            subs = self._extract_subdomains_from_text(result.output)
            return await self._store_subdomains(subs, "massdns")
        return 0

    async def _run_sub_019(self) -> int:
        """Check for wildcard DNS responses to filter false positives."""
        import dns.resolver
        wildcard_ips = set()
        try:
            # Query a random non-existent subdomain
            random_sub = f"this-definitely-does-not-exist-8374.{self.target}"
            answers = dns.resolver.resolve(random_sub, "A")
            wildcard_ips = {str(r) for r in answers}
        except Exception:
            pass  # No wildcard — good

        if wildcard_ips:
            self.db.add_finding(self.session_id, Finding(
                title=f"Wildcard DNS detected for {self.target}",
                severity=Severity.INFO,
                description=f"Wildcard IPs: {', '.join(wildcard_ips)}",
                source="wildcard_check",
                check_id="sub_019",
            ))
            return 1
        return 0

    async def _run_sub_020(self) -> int:
        """Attempt DNS zone transfer (AXFR) on all authoritative nameservers."""
        import dns.resolver
        import dns.zone
        import dns.query
        count = 0
        try:
            ns_records = dns.resolver.resolve(self.target, "NS")
            for ns in ns_records:
                ns_str = str(ns).rstrip(".")
                try:
                    z = dns.zone.from_xfr(dns.query.xfr(ns_str, self.target, timeout=10))
                    names = [str(n) + "." + self.target for n in z.nodes.keys() if str(n) != "@"]
                    count += await self._store_subdomains(names, "zone_transfer")
                    self.db.add_finding(self.session_id, Finding(
                        title=f"DNS Zone Transfer successful on {ns_str}",
                        severity=Severity.HIGH,
                        description=f"AXFR returned {len(names)} records",
                        source="zone_transfer",
                        check_id="sub_020",
                    ))
                except Exception:
                    pass
        except Exception:
            pass
        return count

    async def _run_sub_021(self) -> int:
        """Enumerate subdomains from JavaScript files on the main domain."""
        resp = await self.http_get(f"https://{self.target}")
        if not resp:
            resp = await self.http_get(f"http://{self.target}")
        if not resp:
            return 0
        # Extract JS URLs
        js_urls = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', resp["text"])
        subs = set()
        for js_url in js_urls[:20]:
            if js_url.startswith("//"):
                js_url = "https:" + js_url
            elif js_url.startswith("/"):
                js_url = f"https://{self.target}{js_url}"
            js_resp = await self.http_get(js_url)
            if js_resp:
                subs.update(self._extract_subdomains_from_text(js_resp["text"]))
        return await self._store_subdomains(list(subs), "js_files")

    async def _run_sub_022(self) -> int:
        """Extract subdomains from SPF records via include mechanisms."""
        import dns.resolver
        subs = set()
        try:
            txt_records = dns.resolver.resolve(self.target, "TXT")
            for r in txt_records:
                txt = str(r).strip('"')
                if "v=spf1" in txt:
                    includes = re.findall(r"include:(\S+)", txt)
                    for inc in includes:
                        if inc.endswith(self.target):
                            subs.add(inc)
                    # Also extract from redirect=
                    redirects = re.findall(r"redirect=(\S+)", txt)
                    for redir in redirects:
                        if redir.endswith(self.target):
                            subs.add(redir)
        except Exception:
            pass
        return await self._store_subdomains(list(subs), "spf_records")

    async def _run_sub_023(self) -> int:
        """Extract subdomains from DMARC aggregate reports (rua tag)."""
        import dns.resolver
        subs = set()
        try:
            dmarc = dns.resolver.resolve(f"_dmarc.{self.target}", "TXT")
            for r in dmarc:
                txt = str(r).strip('"')
                rua = re.findall(r"rua=mailto:([^;\s]+)", txt)
                ruf = re.findall(r"ruf=mailto:([^;\s]+)", txt)
                for email in rua + ruf:
                    domain = email.split("@")[-1]
                    if domain.endswith(self.target):
                        subs.add(domain)
        except Exception:
            pass
        return await self._store_subdomains(list(subs), "dmarc_records")

    async def _run_sub_024(self) -> int:
        """Google Transparency Report for certificate search."""
        data = await self.http_get_json(
            f"https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?include_expired=true&include_subdomains=true&domain={self.target}",
        )
        # Google wraps response in )]}' prefix
        if data:
            subs = self._extract_subdomains_from_text(str(data))
            return await self._store_subdomains(subs, "google_transparency")
        return 0

    async def _run_sub_025(self, probe_live: bool = True) -> int:
        """Check for subdomain takeover vulnerability on all discovered subdomains."""
        existing = self.db.get_subdomains(self.session_id)
        if not existing:
            return 0
        # First classify dead/live hosts so takeover evidence is not confused
        # with ordinary dead subdomains.
        if probe_live:
            await self._probe_live_hosts(existing)
        # CNAME fingerprints for takeover-vulnerable services
        takeover_fingerprints = {
            "github.io": "GitHub Pages",
            "herokuapp.com": "Heroku",
            "herokudns.com": "Heroku",
            "amazonaws.com": "AWS S3",
            "cloudfront.net": "AWS CloudFront",
            "azurewebsites.net": "Azure",
            "azure-api.net": "Azure",
            "cloudapp.net": "Azure",
            "trafficmanager.net": "Azure Traffic Manager",
            "pantheonsite.io": "Pantheon",
            "domains.tumblr.com": "Tumblr",
            "wpengine.com": "WP Engine",
            "ghost.io": "Ghost",
            "myshopify.com": "Shopify",
            "surge.sh": "Surge",
            "bitbucket.io": "Bitbucket",
            "ghost.org": "Ghost",
            "freshdesk.com": "Freshdesk",
            "zendesk.com": "Zendesk",
            "readme.io": "ReadMe",
            "statuspage.io": "Statuspage",
            "youtrack.cloud": "YouTrack",
            "netlify.app": "Netlify",
            "fly.dev": "Fly.io",
            "vercel.app": "Vercel",
            "render.com": "Render",
        }
        count = 0
        import dns.resolver
        for sub_record in existing:
            subdomain = sub_record["subdomain"]
            try:
                cnames = dns.resolver.resolve(subdomain, "CNAME")
                for cname in cnames:
                    cname_str = str(cname).rstrip(".")
                    for fp, service in takeover_fingerprints.items():
                        if cname_str.endswith(fp):
                            # Try to verify: if the CNAME target doesn't resolve, it's dangling.
                            # HTTP responses are collected as supporting evidence only.
                            try:
                                dns.resolver.resolve(cname_str, "A")
                            except dns.resolver.NXDOMAIN:
                                self.db.add_finding(self.session_id, Finding(
                                    title=f"Potential subdomain takeover: {subdomain}",
                                    severity=Severity.HIGH,
                                    url=f"https://{subdomain}",
                                    description=f"CNAME points to {cname_str} ({service}) but target is NXDOMAIN",
                                    evidence=f"CNAME: {subdomain} -> {cname_str}",
                                    source="takeover_check",
                                    check_id="sub_025",
                                ))
                                count += 1
                            except Exception:
                                pass
            except Exception:
                pass
        return count

    async def finalize_recon(self) -> dict:
        """Run post-enumeration liveness and takeover checks over all assets."""
        records = self.db.get_subdomains(self.session_id)
        live = await self._probe_live_hosts(records) if records else 0
        takeover = await self._run_sub_025(probe_live=False) if records else 0
        return {"subdomains_checked": len(records), "live_hosts": live, "takeover_candidates": takeover}

    async def _probe_live_hosts(self, records: list[dict]) -> int:
        """Probe discovered subdomains over HTTPS/HTTP and persist liveness."""
        import asyncio
        import re
        semaphore = asyncio.Semaphore(10)

        async def probe(record):
            host = record["subdomain"]
            async with semaphore:
                ips = await self.resolve_dns(host, "A")
                for scheme in ("https", "http"):
                    response = await self.http_get(f"{scheme}://{host}", timeout=min(self.config.timeout, 10))
                    if response:
                        title_match = re.search(r"<title[^>]*>(.*?)</title>", response.get("text", ""), re.I | re.S)
                        title = re.sub(r"\s+", " ", title_match.group(1)).strip()[:200] if title_match else ""
                        self.db.update_subdomain_probe(self.session_id, host, ips, True, response.get("status", 0), title)
                        return 1
                self.db.update_subdomain_probe(self.session_id, host, ips, False, 0, "")
                return 0

        results = await asyncio.gather(*(probe(record) for record in records), return_exceptions=True)
        return sum(1 for result in results if result == 1)

    async def _run_sub_026(self) -> int:
        """Verify DNSSEC configuration and look for misconfigurations."""
        import dns.resolver
        import dns.dnssec
        findings = 0
        try:
            dnskey = dns.resolver.resolve(self.target, "DNSKEY")
            self.db.add_finding(self.session_id, Finding(
                title=f"DNSSEC is configured for {self.target}",
                severity=Severity.INFO,
                description=f"DNSKEY records found: {len(list(dnskey))}",
                source="dnssec_check",
                check_id="sub_026",
            ))
            findings += 1
        except dns.resolver.NoAnswer:
            self.db.add_finding(self.session_id, Finding(
                title=f"DNSSEC NOT configured for {self.target}",
                severity=Severity.LOW,
                description="No DNSKEY records found — DNSSEC not enabled",
                source="dnssec_check",
                check_id="sub_026",
            ))
            findings += 1
        except Exception:
            pass
        return findings

    async def _run_sub_027(self) -> int:
        """nmap DNS brute script."""
        result = await self.run_tool(
            "nmap",
            f"nmap --script dns-brute --script-args dns-brute.threads=10 -sn {self.target}",
            timeout=300,
        )
        if result.success:
            subs = self._extract_subdomains_from_text(result.output)
            return await self._store_subdomains(subs, "nmap_dns_brute")
        return 0

    async def _run_sub_028(self) -> int:
        """Check for dangling CNAME records pointing to expired services."""
        existing = self.db.get_subdomains(self.session_id)
        if not existing:
            return 0
        import dns.resolver
        count = 0
        for sub_record in existing[:200]:
            subdomain = sub_record["subdomain"]
            try:
                cnames = dns.resolver.resolve(subdomain, "CNAME")
                for cname in cnames:
                    cname_str = str(cname).rstrip(".")
                    try:
                        dns.resolver.resolve(cname_str, "A")
                    except dns.resolver.NXDOMAIN:
                        self.db.add_finding(self.session_id, Finding(
                            title=f"Dangling CNAME: {subdomain}",
                            severity=Severity.MEDIUM,
                            description=f"CNAME {cname_str} resolves to NXDOMAIN",
                            source="dangling_cname",
                            check_id="sub_028",
                        ))
                        count += 1
                    except Exception:
                        pass
            except Exception:
                pass
        return count

    async def _run_sub_029(self) -> int:
        """Look for internal IP address leaks in DNS records."""
        existing = self.db.get_subdomains(self.session_id)
        targets = [self.target] + [s["subdomain"] for s in existing[:100]]
        count = 0
        import dns.resolver
        private_ranges = [
            re.compile(r"^10\."),
            re.compile(r"^172\.(1[6-9]|2[0-9]|3[01])\."),
            re.compile(r"^192\.168\."),
            re.compile(r"^127\."),
        ]
        for t in targets:
            try:
                answers = dns.resolver.resolve(t, "A")
                for a in answers:
                    ip = str(a)
                    for priv in private_ranges:
                        if priv.match(ip):
                            self.db.add_finding(self.session_id, Finding(
                                title=f"Internal IP leak in DNS: {t} -> {ip}",
                                severity=Severity.MEDIUM,
                                description=f"Private IP {ip} exposed in A record for {t}",
                                source="internal_ip_leak",
                                check_id="sub_029",
                            ))
                            count += 1
            except Exception:
                pass
        return count

    async def _run_sub_030(self) -> int:
        """sublist3r — all search engine modules enabled."""
        result = await self.run_tool(
            "sublist3r",
            f"sublist3r -d {self.target} -t 10 -o /dev/stdout",
        )
        if result.success:
            subs = self._extract_subdomains_from_text(result.output)
            return await self._store_subdomains(subs, "sublist3r")
        return 0

    async def _run_sub_031(self) -> int:
        """Check for subdomains in robots.txt and sitemap.xml."""
        subs = set()
        for path in ["/robots.txt", "/sitemap.xml", "/sitemap_index.xml"]:
            for scheme in ["https", "http"]:
                resp = await self.http_get(f"{scheme}://{self.target}{path}")
                if resp and resp["status"] == 200:
                    subs.update(self._extract_subdomains_from_text(resp["text"]))
        return await self._store_subdomains(list(subs), "robots_sitemap")

    async def _run_sub_032(self) -> int:
        """Search GitHub repositories for subdomain references."""
        if not self.keys.github_token:
            return 0
        data = await self.http_get_json(
            f"https://api.github.com/search/code?q={self.target}+in:file&per_page=100",
            headers={"Authorization": f"token {self.keys.github_token}"},
        )
        if data and "items" in data:
            subs = set()
            for item in data["items"]:
                text = item.get("text_matches", "")
                subs.update(self._extract_subdomains_from_text(str(text)))
            return await self._store_subdomains(list(subs), "github")
        return 0

    async def _run_sub_033(self) -> int:
        """Check Stack Overflow for subdomain leaks."""
        data = await self.http_get(
            f"https://api.stackexchange.com/2.3/search?order=desc&sort=relevance&intitle={self.target}&site=stackoverflow"
        )
        if data and data["status"] == 200:
            subs = self._extract_subdomains_from_text(data["text"])
            return await self._store_subdomains(subs, "stackoverflow")
        return 0

    async def _run_sub_034(self) -> int:
        """Chaos dataset from ProjectDiscovery."""
        if not self.keys.chaos:
            return 0
        data = await self.http_get_json(
            f"https://dns.projectdiscovery.io/dns/{self.target}/subdomains",
            headers={"Authorization": self.keys.chaos},
        )
        if data and "subdomains" in data:
            subs = [f"{s}.{self.target}" for s in data["subdomains"]]
            return await self._store_subdomains(subs, "chaos")
        return 0

    async def _run_sub_035(self) -> int:
        """Check for subdomains embedded in APK/IPA (placeholder)."""
        # This requires actual APK/IPA files which we won't have in recon
        # We can search for APK on public stores and decompile
        return 0

    async def _run_sub_036(self) -> int:
        """Rapid7 Open Data (Project Sonar) — forward DNS lookup."""
        data = await self.http_get_json(
            f"https://sonar.omnisint.io/subdomains/{self.target}"
        )
        if data and isinstance(data, list):
            subs = [s for s in data if s.endswith(self.target)]
            return await self._store_subdomains(subs, "rapid7_sonar")
        return 0

    async def _run_sub_037(self) -> int:
        """Enumerate cloud subdomains (AWS S3, Azure Blob, GCP Storage)."""
        cloud_patterns = [
            f"{self.target.split('.')[0]}.s3.amazonaws.com",
            f"{self.target.split('.')[0]}.s3-us-west-1.amazonaws.com",
            f"{self.target.split('.')[0]}.s3-us-east-1.amazonaws.com",
            f"{self.target.split('.')[0]}.blob.core.windows.net",
            f"{self.target.split('.')[0]}.azurewebsites.net",
            f"{self.target.split('.')[0]}.storage.googleapis.com",
            f"{self.target.split('.')[0]}.appspot.com",
            f"{self.target.split('.')[0]}.firebaseapp.com",
        ]
        count = 0
        for pattern in cloud_patterns:
            resp = await self.http_get(f"https://{pattern}")
            if resp and resp["status"] not in [0, 404]:
                self.db.add_finding(self.session_id, Finding(
                    title=f"Cloud asset found: {pattern}",
                    severity=Severity.INFO,
                    url=f"https://{pattern}",
                    description=f"HTTP {resp['status']}",
                    source="cloud_enum",
                    check_id="sub_037",
                ))
                count += 1
        return count

    async def _run_sub_038(self) -> int:
        """Check for subdomains leaked in email headers (SPF/DKIM/DMARC)."""
        import dns.resolver
        subs = set()
        # Check various email-related records
        for prefix in ["_dmarc", "mail", "smtp", "mx", "email", "imap", "pop3"]:
            fqdn = f"{prefix}.{self.target}"
            try:
                dns.resolver.resolve(fqdn, "A")
                subs.add(fqdn)
            except Exception:
                pass
        # Check MX records
        try:
            mx_records = dns.resolver.resolve(self.target, "MX")
            for mx in mx_records:
                mx_host = str(mx.exchange).rstrip(".")
                if mx_host.endswith(self.target):
                    subs.add(mx_host)
        except Exception:
            pass
        return await self._store_subdomains(list(subs), "email_headers")

    async def _run_sub_039(self) -> int:
        """Recon.dev API for subdomain enumeration."""
        if not self.keys.recon_dev:
            # Try free endpoint
            data = await self.http_get_json(
                f"https://recon.dev/api/search?key=apikey&domain={self.target}"
            )
        else:
            data = await self.http_get_json(
                f"https://recon.dev/api/search?key={self.keys.recon_dev}&domain={self.target}"
            )
        if data and isinstance(data, list):
            subs = set()
            for entry in data:
                raw = entry.get("rawDomains", [])
                if isinstance(raw, list):
                    for d in raw:
                        if d.endswith(self.target):
                            subs.add(d)
            return await self._store_subdomains(list(subs), "recon_dev")
        return 0

    async def _run_sub_040(self) -> int:
        """Check for Punycode/IDN subdomain variants for homograph attacks."""
        # Generate common homograph variants
        homograph_map = {
            "a": ["а", "ä"],  # Cyrillic а
            "e": ["е", "ë"],
            "o": ["о", "ö"],
            "c": ["с"],
            "p": ["р"],
        }
        base = self.target.split(".")[0]
        variants = set()
        for i, ch in enumerate(base):
            if ch.lower() in homograph_map:
                for alt in homograph_map[ch.lower()]:
                    variant = base[:i] + alt + base[i+1:]
                    import encodings.idna
                    try:
                        puny = variant.encode("idna").decode()
                        variants.add(f"{puny}.{'.'.join(self.target.split('.')[1:])}")
                    except Exception:
                        pass
        count = 0
        for v in list(variants)[:20]:
            ips = await self.resolve_dns(v)
            if ips:
                self.db.add_finding(self.session_id, Finding(
                    title=f"IDN/Punycode variant resolves: {v}",
                    severity=Severity.MEDIUM,
                    description=f"Homograph domain {v} resolves to {', '.join(ips)}",
                    source="punycode_check",
                    check_id="sub_040",
                ))
                count += 1
        return count

    async def _run_sub_041(self) -> int:
        """Internet Archive Wayback CDX API for subdomains."""
        # This is similar to sub_009 but uses different parameters
        resp = await self.http_get(
            f"https://web.archive.org/cdx/search/cdx?url=*.{self.target}&output=json&fl=original&collapse=urlkey&limit=5000",
            timeout=60,
        )
        if resp and resp["status"] == 200:
            subs = self._extract_subdomains_from_text(resp["text"])
            return await self._store_subdomains(subs, "wayback_cdx")
        return 0

    async def _run_sub_042(self) -> int:
        """Look for subdomains in Wappalyzer/technology detection."""
        # Use built-with or similar API
        resp = await self.http_get(
            f"https://api.wappalyzer.com/v2/lookup/?urls=https://{self.target}",
        )
        if resp and resp["status"] == 200:
            subs = self._extract_subdomains_from_text(resp["text"])
            return await self._store_subdomains(subs, "wappalyzer")
        return 0

    async def _run_sub_043(self) -> int:
        """BufferOver.run for subdomain data from Rapid7 Sonar."""
        data = await self.http_get_json(
            f"https://dns.bufferover.run/dns?q=.{self.target}"
        )
        if data and "FDNS_A" in data:
            subs = set()
            for entry in data.get("FDNS_A", []) or []:
                parts = entry.split(",")
                if len(parts) >= 2 and parts[1].endswith(self.target):
                    subs.add(parts[1])
            return await self._store_subdomains(list(subs), "bufferover")
        return 0

    async def _run_sub_044(self) -> int:
        """Common Crawl data index for subdomains."""
        resp = await self.http_get(
            f"https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.{self.target}&output=json&limit=500",
            timeout=60,
        )
        if resp and resp["status"] == 200:
            subs = self._extract_subdomains_from_text(resp["text"])
            return await self._store_subdomains(subs, "common_crawl")
        return 0

    async def _run_sub_045(self) -> int:
        """DNSrecon for SRV record enumeration."""
        result = await self.run_tool(
            "dnsrecon",
            f"dnsrecon -d {self.target} -t srv",
        )
        if result.success:
            subs = self._extract_subdomains_from_text(result.output)
            return await self._store_subdomains(subs, "dnsrecon_srv")
        # Fallback: pure Python SRV lookup
        import dns.resolver
        subs = set()
        srv_prefixes = [
            "_sip._tcp", "_sip._udp", "_sipfederationtls._tcp",
            "_xmpp-server._tcp", "_xmpp-client._tcp",
            "_http._tcp", "_https._tcp",
            "_ldap._tcp", "_kerberos._tcp", "_kpasswd._tcp",
            "_imap._tcp", "_imaps._tcp", "_pop3._tcp", "_pop3s._tcp",
            "_smtp._tcp", "_submission._tcp",
            "_autodiscover._tcp", "_caldav._tcp", "_carddav._tcp",
        ]
        for prefix in srv_prefixes:
            try:
                records = dns.resolver.resolve(f"{prefix}.{self.target}", "SRV")
                for r in records:
                    target_host = str(r.target).rstrip(".")
                    if target_host.endswith(self.target):
                        subs.add(target_host)
            except Exception:
                pass
        return await self._store_subdomains(list(subs), "srv_records")

    async def _run_sub_046(self) -> int:
        """HTTP certificate parsing (openssl s_client or Python SSL)."""
        import ssl
        import socket
        subs = set()
        existing = [self.target] + [s["subdomain"] for s in self.db.get_subdomains(self.session_id)[:50]]
        for host in existing:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, 443), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert(binary_form=False)
                        if cert:
                            # Extract SANs
                            sans = cert.get("subjectAltName", [])
                            for _, value in sans:
                                v = value.lstrip("*.")
                                if v.endswith(self.target):
                                    subs.add(v)
            except Exception:
                pass
        return await self._store_subdomains(list(subs), "ssl_cert_parse")

    async def _run_sub_047(self) -> int:
        """CertSpotter API for certificate transparency monitoring."""
        data = await self.http_get_json(
            f"https://api.certspotter.com/v1/issuances?domain={self.target}&include_subdomains=true&expand=dns_names"
        )
        if data and isinstance(data, list):
            subs = set()
            for entry in data:
                for name in entry.get("dns_names", []):
                    n = name.lstrip("*.")
                    if n.endswith(self.target):
                        subs.add(n)
            return await self._store_subdomains(list(subs), "certspotter")
        return 0

    async def _run_sub_048(self) -> int:
        """FOFA search engine for subdomains."""
        if not self.keys.fofa_email or not self.keys.fofa_key:
            return 0
        import base64
        query = base64.b64encode(f'domain="{self.target}"'.encode()).decode()
        data = await self.http_get_json(
            f"https://fofa.info/api/v1/search/all?email={self.keys.fofa_email}&key={self.keys.fofa_key}&qbase64={query}&size=1000&fields=host"
        )
        if data and "results" in data:
            subs = set()
            for result in data["results"]:
                host = result[0] if isinstance(result, list) else result
                if isinstance(host, str) and host.endswith(self.target):
                    subs.add(host)
            return await self._store_subdomains(list(subs), "fofa")
        return 0

    async def _run_sub_049(self) -> int:
        """ZoomEye search engine for subdomains."""
        if not self.keys.zoomeye:
            return 0
        data = await self.http_get_json(
            f"https://api.zoomeye.org/domain/search?q={self.target}&type=0&page=1",
            headers={"API-KEY": self.keys.zoomeye},
        )
        if data and "list" in data:
            subs = set()
            for item in data["list"]:
                name = item.get("name", "")
                if name.endswith(self.target):
                    subs.add(name)
            return await self._store_subdomains(list(subs), "zoomeye")
        return 0

    async def _run_sub_050(self) -> int:
        """DorkAssistant — automated Google dork subdomain enumeration."""
        # Implement as a multi-dork approach
        dorks = [
            f"site:*.{self.target}",
            f"site:{self.target} -www",
            f"inurl:{self.target}",
        ]
        subs = set()
        for dork in dorks:
            resp = await self.http_get(
                f"https://html.duckduckgo.com/html/?q={quote(dork)}",
            )
            if resp and resp["status"] == 200:
                subs.update(self._extract_subdomains_from_text(resp["text"]))
        return await self._store_subdomains(list(subs), "dork_assistant")
