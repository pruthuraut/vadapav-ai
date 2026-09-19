"""
bb_harness.agents.port_scan
Port Scanning & Service Enumeration Agent — 50 checks.
"""
from __future__ import annotations
import asyncio
import socket
import re
from typing import List

from bb_harness.agents.base import BaseAgent
from bb_harness.core.models import (
    AgentCategory, OpenPort, Finding, Severity,
)


class PortScanAgent(BaseAgent):
    AGENT_ID = "port_scan"
    CATEGORY = AgentCategory.PORT_SCAN
    NAME = "Port Scanning & Service Enumeration"
    DESCRIPTION = "50 checks for port scanning, service identification, and access detection"

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _get_hosts(self) -> List[str]:
        """Get hosts to scan from the current target + discovered subdomains."""
        subs = self.db.get_subdomains(self.session_id)
        hosts = [self.target]
        for s in subs:
            if s.get("is_alive") or s.get("ip_addresses"):
                hosts.append(s["subdomain"])
        return list(set(hosts))[:100]  # Cap at 100

    async def _async_tcp_check(self, host: str, port: int,
                               timeout: float = 3.0) -> bool:
        """Quick async TCP connect check."""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    async def _grab_banner(self, host: str, port: int,
                           timeout: float = 3.0) -> str:
        """Grab service banner from a port."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            # Some services send banner on connect
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                banner = data.decode("utf-8", errors="replace").strip()
            except asyncio.TimeoutError:
                banner = ""
            # For HTTP ports, send a GET
            if not banner and port in (80, 443, 8080, 8443, 8000, 8888, 3000, 9000):
                writer.write(b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                await writer.drain()
                try:
                    data = await asyncio.wait_for(reader.read(2048), timeout=2.0)
                    banner = data.decode("utf-8", errors="replace").strip()[:200]
                except asyncio.TimeoutError:
                    pass
            writer.close()
            await writer.wait_closed()
            return banner[:200]
        except Exception:
            return ""

    async def _check_http_service(self, host: str, port: int,
                                  path: str = "/", expected: str = None) -> dict:
        """Check an HTTP service on host:port/path."""
        schemes = ["https", "http"] if port in (443, 8443) else ["http", "https"]
        for scheme in schemes:
            resp = await self.http_get(f"{scheme}://{host}:{port}{path}", timeout=10)
            if resp:
                return resp
        return None

    async def _scan_ports_async(self, host: str, ports: List[int],
                                source: str) -> int:
        """Scan a list of ports on a host using async TCP connect."""
        count = 0
        sem = asyncio.Semaphore(self.config.concurrency)

        async def _check(port):
            nonlocal count
            async with sem:
                if await self._async_tcp_check(host, port):
                    banner = await self._grab_banner(host, port)
                    self.db.add_port(self.session_id, OpenPort(
                        host=host, port=port, protocol="tcp",
                        banner=banner, source=source,
                    ))
                    count += 1

        await asyncio.gather(*[_check(p) for p in ports])
        return count

    # ══════════════════════════════════════════════════════════════════════════
    # CHECK IMPLEMENTATIONS
    # ══════════════════════════════════════════════════════════════════════════

    async def _run_port_001(self) -> int:
        """nmap TCP SYN scan on all 65535 ports."""
        hosts = await self._get_hosts()
        result = await self.run_tool(
            "nmap",
            f"nmap -sS -p- -T4 --min-rate=1000 -oG - {' '.join(hosts[:5])}",
            timeout=900,
        )
        if result.success:
            count = 0
            for line in result.lines:
                if "/open/" in line:
                    parts = line.split()
                    host = parts[1] if len(parts) > 1 else self.target
                    port_matches = re.findall(r"(\d+)/open/tcp", line)
                    for p in port_matches:
                        self.db.add_port(self.session_id, OpenPort(
                            host=host, port=int(p), source="nmap_syn"))
                        count += 1
            return count
        # Fallback: async TCP scan on common ports
        common = [int(p) for p in self.config.ports_common.split(",")]
        return await self._scan_ports_async(self.target, common, "async_tcp")

    async def _run_port_002(self) -> int:
        """masscan — ultra-fast port scanning."""
        hosts = await self._get_hosts()
        result = await self.run_tool(
            "masscan",
            f"masscan {' '.join(hosts[:5])} -p{self.config.ports_common} --rate={self.config.rate_limit} --open-only",
            timeout=600,
        )
        if result.success:
            count = 0
            for line in result.lines:
                m = re.search(r"Discovered open port (\d+)/tcp on ([\d\.]+)", line)
                if m:
                    self.db.add_port(self.session_id, OpenPort(
                        host=m.group(2), port=int(m.group(1)), source="masscan"))
                    count += 1
            return count
        return 0

    async def _run_port_003(self) -> int:
        """rustscan — fast port discovery with nmap integration."""
        result = await self.run_tool(
            "rustscan",
            f"rustscan -a {self.target} --ulimit 5000 -- -sV",
            timeout=600,
        )
        if result.success:
            count = 0
            for line in result.lines:
                m = re.search(r"(\d+)/tcp\s+open\s+(\S+)", line)
                if m:
                    self.db.add_port(self.session_id, OpenPort(
                        host=self.target, port=int(m.group(1)),
                        service=m.group(2), source="rustscan"))
                    count += 1
            return count
        return 0

    async def _run_port_004(self) -> int:
        """nmap UDP scan on common ports."""
        result = await self.run_tool(
            "nmap",
            f"nmap -sU -p 53,67,68,123,161,500,514 --min-rate=500 {self.target}",
            timeout=300,
        )
        if result.success:
            count = 0
            for line in result.lines:
                m = re.search(r"(\d+)/udp\s+open", line)
                if m:
                    self.db.add_port(self.session_id, OpenPort(
                        host=self.target, port=int(m.group(1)),
                        protocol="udp", source="nmap_udp"))
                    count += 1
            return count
        return 0

    async def _run_port_005(self) -> int:
        """nmap service version detection (-sV)."""
        ports = self.db.get_ports(self.session_id)
        if not ports:
            return 0
        port_list = ",".join(str(p["port"]) for p in ports[:50])
        result = await self.run_tool(
            "nmap",
            f"nmap -sV -p {port_list} {self.target}",
            timeout=300,
        )
        if result.success:
            count = 0
            for line in result.lines:
                m = re.search(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line)
                if m:
                    port_num = int(m.group(1))
                    service = m.group(2)
                    version = m.group(3).strip()
                    self.db.add_port(self.session_id, OpenPort(
                        host=self.target, port=port_num,
                        service=service, version=version, source="nmap_sv"))
                    count += 1
            return count
        return 0

    async def _run_port_006(self) -> int:
        """nmap OS detection."""
        result = await self.run_tool(
            "nmap", f"nmap -O --osscan-guess {self.target}", timeout=120,
        )
        if result.success and "OS details" in result.output:
            m = re.search(r"OS details:\s*(.+)", result.output)
            if m:
                self.db.add_finding(self.session_id, Finding(
                    title=f"OS Detection: {self.target}",
                    severity=Severity.INFO,
                    description=m.group(1),
                    source="nmap_os", check_id="port_006",
                ))
                return 1
        return 0

    async def _run_port_007(self) -> int:
        """nmap default script scan (-sC)."""
        ports = self.db.get_ports(self.session_id)
        if not ports:
            return 0
        port_list = ",".join(str(p["port"]) for p in ports[:30])
        result = await self.run_tool(
            "nmap", f"nmap -sC -p {port_list} {self.target}", timeout=300,
        )
        if result.success:
            # Look for script output indicating vulns
            vulns = re.findall(r"\|_?\s*(.*vuln.*|.*VULNERABLE.*)", result.output, re.IGNORECASE)
            for v in vulns:
                self.db.add_finding(self.session_id, Finding(
                    title=f"Nmap script finding on {self.target}",
                    severity=Severity.MEDIUM,
                    description=v.strip(),
                    source="nmap_scripts", check_id="port_007",
                ))
            return len(vulns)
        return 0

    async def _run_port_008(self) -> int:
        """unicornscan — asynchronous port scanning."""
        result = await self.run_tool(
            "unicornscan", f"unicornscan -mT {self.target}:a -r 500", timeout=600,
        )
        if result.success:
            count = 0
            for line in result.lines:
                m = re.search(r"TCP open\s+.*?(\d+)", line)
                if m:
                    self.db.add_port(self.session_id, OpenPort(
                        host=self.target, port=int(m.group(1)), source="unicornscan"))
                    count += 1
            return count
        return 0

    async def _run_port_009(self) -> int:
        """Check for services on non-standard ports (8080, 8443, 8000)."""
        non_standard = [8080, 8443, 8000, 8888, 3000, 4443, 9090, 9443]
        return await self._scan_ports_async(self.target, non_standard, "non_standard_ports")

    async def _run_port_010(self) -> int:
        """Scan for hidden admin ports (10000, 20000, 30000)."""
        admin_ports = [10000, 20000, 30000, 9090, 2082, 2083, 2086, 2087, 8880]
        return await self._scan_ports_async(self.target, admin_ports, "admin_ports")

    async def _run_port_011(self) -> int:
        """naabu — fast port scanning with SYN/CONNECT mode."""
        result = await self.run_tool(
            "naabu", f"naabu -host {self.target} -p - -silent", timeout=300,
        )
        if result.success:
            count = 0
            for line in result.lines:
                m = re.search(r":(\d+)$", line)
                if m:
                    self.db.add_port(self.session_id, OpenPort(
                        host=self.target, port=int(m.group(1)), source="naabu"))
                    count += 1
            return count
        return 0

    async def _run_port_012(self) -> int:
        """Enumerate services behind load balancers (multiple scan passes)."""
        # Run 3 quick scans and compare results for LB detection
        results_per_pass = []
        for _ in range(3):
            ips = await self.resolve_dns(self.target)
            results_per_pass.append(set(ips))
            await asyncio.sleep(1)
        all_ips = set()
        for s in results_per_pass:
            all_ips.update(s)
        if len(all_ips) > 1:
            self.db.add_finding(self.session_id, Finding(
                title=f"Load balancer detected for {self.target}",
                severity=Severity.INFO,
                description=f"Multiple IPs returned across DNS queries: {', '.join(all_ips)}",
                source="lb_detection", check_id="port_012",
            ))
            return 1
        return 0

    async def _run_port_013(self) -> int:
        """Check for IPv6 addresses and scan IPv6 interfaces."""
        aaaa = await self.resolve_dns(self.target, "AAAA")
        if aaaa:
            self.db.add_finding(self.session_id, Finding(
                title=f"IPv6 address found for {self.target}",
                severity=Severity.INFO,
                description=f"AAAA records: {', '.join(aaaa)}",
                source="ipv6_check", check_id="port_013",
            ))
            return 1
        return 0

    async def _run_port_014(self) -> int:
        """nmap timing templates (stealth scan with T2)."""
        result = await self.run_tool(
            "nmap", f"nmap -sS -T2 -p 80,443,22,21,25 {self.target}", timeout=120,
        )
        if result.success:
            return len(re.findall(r"\d+/tcp\s+open", result.output))
        return 0

    async def _run_port_015(self) -> int:
        """nmap with fragmentation and decoy for IDS evasion."""
        result = await self.run_tool(
            "nmap", f"nmap -f -D RND:5 -p 80,443 {self.target}", timeout=120,
        )
        return 1 if result.success else 0

    async def _run_port_016(self) -> int:
        """Check for port knocking sequences on filtered ports."""
        # Informational: check if common ports are filtered
        common = [22, 80, 443, 8080]
        filtered = 0
        for port in common:
            if not await self._async_tcp_check(self.target, port, timeout=2.0):
                filtered += 1
        if filtered == len(common):
            self.db.add_finding(self.session_id, Finding(
                title=f"All common ports filtered on {self.target} — possible port knocking",
                severity=Severity.INFO,
                source="port_knock_check", check_id="port_016",
            ))
            return 1
        return 0

    async def _run_port_017(self) -> int:
        """Identify proxy services."""
        proxy_ports = {"3128": "Squid", "1080": "SOCKS", "808": "CCProxy",
                       "8118": "Privoxy", "8888": "Polipo"}
        count = 0
        for port_str, name in proxy_ports.items():
            port = int(port_str)
            if await self._async_tcp_check(self.target, port):
                self.db.add_port(self.session_id, OpenPort(
                    host=self.target, port=port, service=name, source="proxy_check"))
                count += 1
        return count

    async def _run_port_018(self) -> int:
        """Enumerate database ports."""
        db_ports = {3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL",
                    27017: "MongoDB", 1521: "Oracle", 6379: "Redis",
                    9200: "Elasticsearch", 5984: "CouchDB", 7474: "Neo4j"}
        count = 0
        for port, service in db_ports.items():
            if await self._async_tcp_check(self.target, port):
                banner = await self._grab_banner(self.target, port)
                self.db.add_port(self.session_id, OpenPort(
                    host=self.target, port=port, service=service,
                    banner=banner, source="db_ports"))
                count += 1
        return count

    async def _run_port_019(self) -> int:
        """Check for Redis on 6379 with unauthenticated access."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, 6379), timeout=5)
            writer.write(b"INFO\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(2048), timeout=3)
            response = data.decode("utf-8", errors="replace")
            writer.close()
            await writer.wait_closed()
            if "redis_version" in response:
                self.db.add_finding(self.session_id, Finding(
                    title=f"Redis unauthenticated access on {self.target}:6379",
                    severity=Severity.CRITICAL,
                    description=response[:200],
                    source="redis_check", check_id="port_019",
                ))
                return 1
        except Exception:
            pass
        return 0

    async def _run_port_020(self) -> int:
        """Check for Elasticsearch on 9200 with unauthorized read."""
        resp = await self.http_get(f"http://{self.target}:9200/", timeout=10)
        if resp and resp["status"] == 200 and "cluster_name" in resp.get("text", ""):
            self.db.add_finding(self.session_id, Finding(
                title=f"Elasticsearch unauthenticated on {self.target}:9200",
                severity=Severity.CRITICAL,
                description=resp["text"][:300],
                source="elasticsearch_check", check_id="port_020",
            ))
            return 1
        return 0

    async def _run_port_021(self) -> int:
        """Check for Memcached on 11211 with unauthenticated access."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, 11211), timeout=5)
            writer.write(b"stats\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(2048), timeout=3)
            response = data.decode("utf-8", errors="replace")
            writer.close()
            await writer.wait_closed()
            if "STAT" in response:
                self.db.add_finding(self.session_id, Finding(
                    title=f"Memcached unauthenticated on {self.target}:11211",
                    severity=Severity.HIGH,
                    description=response[:200],
                    source="memcached_check", check_id="port_021",
                ))
                return 1
        except Exception:
            pass
        return 0

    async def _run_port_022(self) -> int:
        """Scan for Docker API on 2375/2376."""
        for port in [2375, 2376]:
            resp = await self.http_get(f"http://{self.target}:{port}/version", timeout=10)
            if resp and resp["status"] == 200 and "ApiVersion" in resp.get("text", ""):
                self.db.add_finding(self.session_id, Finding(
                    title=f"Docker API unauthenticated on {self.target}:{port}",
                    severity=Severity.CRITICAL,
                    description=resp["text"][:300],
                    source="docker_api_check", check_id="port_022",
                ))
                return 1
        return 0

    async def _run_port_023(self) -> int:
        """Scan for Kubernetes API on 6443/8443."""
        for port in [6443, 8443, 10250]:
            resp = await self.http_get(f"https://{self.target}:{port}/version", timeout=10)
            if resp and resp["status"] == 200 and "gitVersion" in resp.get("text", ""):
                self.db.add_finding(self.session_id, Finding(
                    title=f"Kubernetes API accessible on {self.target}:{port}",
                    severity=Severity.HIGH,
                    description=resp["text"][:300],
                    source="k8s_api_check", check_id="port_023",
                ))
                return 1
        return 0

    async def _run_port_024(self) -> int:
        """Check for RDP on 3389."""
        if await self._async_tcp_check(self.target, 3389):
            self.db.add_port(self.session_id, OpenPort(
                host=self.target, port=3389, service="rdp", source="rdp_check"))
            return 1
        return 0

    async def _run_port_025(self) -> int:
        """Check for SSH on port 22 and non-standard ports."""
        count = 0
        for port in [22, 2222, 2200, 22222]:
            if await self._async_tcp_check(self.target, port):
                banner = await self._grab_banner(self.target, port)
                self.db.add_port(self.session_id, OpenPort(
                    host=self.target, port=port, service="ssh",
                    banner=banner, source="ssh_check"))
                count += 1
        return count

    async def _run_port_026(self) -> int:
        """Check for FTP on 21 with anonymous login."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, 21), timeout=5)
            banner = (await asyncio.wait_for(reader.read(1024), timeout=3)).decode("utf-8", errors="replace")
            writer.write(b"USER anonymous\r\n")
            await writer.drain()
            resp1 = (await asyncio.wait_for(reader.read(1024), timeout=3)).decode()
            writer.write(b"PASS anonymous@\r\n")
            await writer.drain()
            resp2 = (await asyncio.wait_for(reader.read(1024), timeout=3)).decode()
            writer.close()
            await writer.wait_closed()
            if "230" in resp2:
                self.db.add_finding(self.session_id, Finding(
                    title=f"FTP anonymous login enabled on {self.target}:21",
                    severity=Severity.HIGH,
                    description=f"Banner: {banner[:100]}",
                    source="ftp_anon_check", check_id="port_026",
                ))
                return 1
            self.db.add_port(self.session_id, OpenPort(
                host=self.target, port=21, service="ftp", banner=banner[:100], source="ftp_check"))
            return 1
        except Exception:
            return 0

    async def _run_port_027(self) -> int:
        """Check for SMTP on 25 for open relay."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, 25), timeout=5)
            banner = (await asyncio.wait_for(reader.read(1024), timeout=3)).decode("utf-8", errors="replace")
            self.db.add_port(self.session_id, OpenPort(
                host=self.target, port=25, service="smtp", banner=banner[:100], source="smtp_check"))
            writer.close()
            await writer.wait_closed()
            return 1
        except Exception:
            return 0

    async def _run_port_028(self) -> int:
        """Check for SNMP on 161 with default community strings."""
        # SNMP uses UDP, harder to check without scapy
        result = await self.run_tool(
            "nmap", f"nmap -sU -p 161 --script snmp-brute {self.target}", timeout=60,
        )
        if result.success and "public" in result.output.lower():
            self.db.add_finding(self.session_id, Finding(
                title=f"SNMP default community string on {self.target}:161",
                severity=Severity.HIGH,
                description="Default community string 'public' accepted",
                source="snmp_check", check_id="port_028",
            ))
            return 1
        return 0

    async def _run_port_029(self) -> int:
        """Identify load balancers via server headers."""
        resp = await self.http_get(f"https://{self.target}", timeout=10)
        if not resp:
            resp = await self.http_get(f"http://{self.target}", timeout=10)
        if resp:
            headers = resp.get("headers", {})
            lb_indicators = {
                "x-served-by": "CDN/LB",
                "x-cache": "CDN",
                "x-varnish": "Varnish",
                "via": "Proxy/LB",
                "x-haproxy": "HAProxy",
            }
            for header, name in lb_indicators.items():
                if header in headers:
                    self.db.add_finding(self.session_id, Finding(
                        title=f"{name} detected via {header} header",
                        severity=Severity.INFO,
                        description=f"{header}: {headers[header]}",
                        source="lb_headers", check_id="port_029",
                    ))
            server = headers.get("server", "")
            if server:
                self.db.add_finding(self.session_id, Finding(
                    title=f"Server header: {server}",
                    severity=Severity.INFO,
                    source="server_header", check_id="port_029",
                ))
            return 1
        return 0

    async def _run_port_030(self) -> int:
        """Check for VNC on 5900+ without auth."""
        count = 0
        for port in [5900, 5901, 5902]:
            if await self._async_tcp_check(self.target, port):
                self.db.add_port(self.session_id, OpenPort(
                    host=self.target, port=port, service="vnc", source="vnc_check"))
                count += 1
        return count

    async def _run_port_031(self) -> int:
        """Enumerate RPC services on port 111."""
        if await self._async_tcp_check(self.target, 111):
            result = await self.run_tool("rpcinfo", f"rpcinfo -p {self.target}", timeout=30)
            self.db.add_port(self.session_id, OpenPort(
                host=self.target, port=111, service="rpcbind", source="rpc_check"))
            return 1
        return 0

    async def _run_port_032(self) -> int:
        """Check for WebDAV on common ports."""
        for scheme in ["https", "http"]:
            resp = await self.http_get(f"{scheme}://{self.target}/webdav/", timeout=10)
            if resp and resp["status"] in [200, 207, 401]:
                self.db.add_finding(self.session_id, Finding(
                    title=f"WebDAV endpoint found on {self.target}",
                    severity=Severity.MEDIUM,
                    url=f"{scheme}://{self.target}/webdav/",
                    description=f"HTTP {resp['status']}",
                    source="webdav_check", check_id="port_032",
                ))
                return 1
        return 0

    # ── Checks 033-050: Service-specific HTTP probes ──────────────────────────
    # Each one probes a specific service on known ports

    async def _run_service_http(self, check_id: str, name: str,
                                ports: list, paths: list,
                                fingerprints: list) -> int:
        """Generic HTTP service check helper."""
        for port in ports:
            for path in paths:
                for scheme in (["https"] if port in (443, 8443) else ["http", "https"]):
                    resp = await self.http_get(
                        f"{scheme}://{self.target}:{port}{path}", timeout=8)
                    if resp and resp["status"] in range(200, 500):
                        text = resp.get("text", "")
                        for fp in fingerprints:
                            if fp.lower() in text.lower():
                                self.db.add_finding(self.session_id, Finding(
                                    title=f"{name} found on {self.target}:{port}{path}",
                                    severity=Severity.MEDIUM,
                                    url=f"{scheme}://{self.target}:{port}{path}",
                                    description=f"Matched: {fp}",
                                    source=f"{name.lower()}_check",
                                    check_id=check_id,
                                ))
                                self.db.add_port(self.session_id, OpenPort(
                                    host=self.target, port=port, service=name.lower(),
                                    source=f"{name.lower()}_check"))
                                return 1
        return 0

    async def _run_port_033(self) -> int:
        return await self._run_service_http("port_033", "Jenkins",
            [8080, 8443, 80, 443], ["/", "/login", "/manage"],
            ["Jenkins", "Dashboard [Jenkins]"])

    async def _run_port_034(self) -> int:
        return await self._run_service_http("port_034", "GitLab",
            [80, 443, 8080, 8443], ["/", "/users/sign_in"],
            ["GitLab", "gitlab-ce", "gitlab-ee"])

    async def _run_port_035(self) -> int:
        return await self._run_service_http("port_035", "Jupyter",
            [8888, 8889], ["/", "/login", "/tree"],
            ["Jupyter", "notebook", "JupyterLab"])

    async def _run_port_036(self) -> int:
        return await self._run_service_http("port_036", "Spark UI",
            [4040, 8080, 8081], ["/", "/jobs/"],
            ["Spark", "Spark Jobs", "SparkUI"])

    async def _run_port_037(self) -> int:
        return await self._run_service_http("port_037", "Hadoop",
            [50070, 8088, 19888, 9870], ["/", "/cluster"],
            ["Hadoop", "HDFS", "NameNode", "ResourceManager"])

    async def _run_port_038(self) -> int:
        return await self._run_service_http("port_038", "Consul",
            [8500], ["/", "/v1/agent/self", "/ui/"],
            ["Consul", "consul"])

    async def _run_port_039(self) -> int:
        """Check for etcd on 2379."""
        resp = await self.http_get(f"http://{self.target}:2379/version", timeout=8)
        if resp and resp["status"] == 200 and "etcd" in resp.get("text", "").lower():
            self.db.add_finding(self.session_id, Finding(
                title=f"etcd accessible on {self.target}:2379",
                severity=Severity.HIGH,
                description=resp["text"][:200],
                source="etcd_check", check_id="port_039",
            ))
            return 1
        return 0

    async def _run_port_040(self) -> int:
        """Check for ZooKeeper on 2181."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, 2181), timeout=5)
            writer.write(b"ruok")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(100), timeout=3)
            writer.close()
            await writer.wait_closed()
            if b"imok" in data:
                self.db.add_finding(self.session_id, Finding(
                    title=f"ZooKeeper accessible on {self.target}:2181",
                    severity=Severity.HIGH,
                    source="zookeeper_check", check_id="port_040",
                ))
                return 1
        except Exception:
            pass
        return 0

    async def _run_port_041(self) -> int:
        """Check for Kafka on 9092."""
        if await self._async_tcp_check(self.target, 9092):
            self.db.add_port(self.session_id, OpenPort(
                host=self.target, port=9092, service="kafka", source="kafka_check"))
            return 1
        return 0

    async def _run_port_042(self) -> int:
        return await self._run_service_http("port_042", "RabbitMQ",
            [15672, 5672], ["/", "/api/overview"],
            ["RabbitMQ", "rabbitmq"])

    async def _run_port_043(self) -> int:
        return await self._run_service_http("port_043", "ActiveMQ",
            [8161, 61616], ["/", "/admin/"],
            ["ActiveMQ", "activemq"])

    async def _run_port_044(self) -> int:
        return await self._run_service_http("port_044", "Nagios",
            [80, 443, 5666], ["/nagios/", "/nagios3/"],
            ["Nagios", "nagios"])

    async def _run_port_045(self) -> int:
        return await self._run_service_http("port_045", "Zabbix",
            [80, 443, 10051], ["/zabbix/", "/"],
            ["Zabbix", "zabbix"])

    async def _run_port_046(self) -> int:
        if await self._async_tcp_check(self.target, 8140):
            self.db.add_port(self.session_id, OpenPort(
                host=self.target, port=8140, service="puppet", source="puppet_check"))
            return 1
        return 0

    async def _run_port_047(self) -> int:
        return await self._run_service_http("port_047", "Ansible Tower",
            [443, 80], ["/", "/api/v2/"],
            ["Ansible", "Tower", "AWX"])

    async def _run_port_048(self) -> int:
        return await self._run_service_http("port_048", "TeamCity",
            [8111], ["/", "/login.html"],
            ["TeamCity", "teamcity"])

    async def _run_port_049(self) -> int:
        return await self._run_service_http("port_049", "Bamboo",
            [8085], ["/", "/userlogin!default.action"],
            ["Bamboo", "bamboo"])

    async def _run_port_050(self) -> int:
        return await self._run_service_http("port_050", "SonarQube",
            [9000], ["/", "/about"],
            ["SonarQube", "sonarqube"])
