"""
bb_harness.core.checklist
Complete TBHM v4.02 recon methodology checklist — 230 checks across 5 categories.
"""
from bb_harness.core.models import CheckItem, CheckStatus, AgentCategory

C = AgentCategory


def build_checklist() -> list[CheckItem]:
    """Build the full 230-check recon methodology checklist."""
    checks = []

    # ══════════════════════════════════════════════════════════════════════════
    # CATEGORY 1: SUBDOMAIN ENUMERATION — 50 checks
    # ══════════════════════════════════════════════════════════════════════════
    sub = [
        ("sub_001", "Use subfinder for passive subdomain enumeration", "subfinder"),
        ("sub_002", "Use amass for deep subdomain discovery with OSINT integration", "amass"),
        ("sub_003", "Use assetfinder to find subdomains from various data sources", "assetfinder"),
        ("sub_004", "Use Findomain for fast subdomain enumeration with certificate transparency", "findomain"),
        ("sub_005", "Use knockpy for subdomain enumeration with DNS zone transfer checks", "knockpy"),
        ("sub_006", "Use DNSdumpster for DNS recon and visual subdomain mapping", ""),
        ("sub_007", "Query crt.sh certificate transparency logs for subdomain enumeration", ""),
        ("sub_008", "Use SecurityTrails API for historical and current DNS records", ""),
        ("sub_009", "Use wayback machine CDX API for discovering old subdomains", ""),
        ("sub_010", "Use VirusTotal domain report for subdomain enumeration from passive DNS", ""),
        ("sub_011", "Use Shodan for subdomain and open port discovery via internet scanning", ""),
        ("sub_012", "Use Censys for certificate-based subdomain discovery at scale", ""),
        ("sub_013", "Use Facebook CT logs (ct.facebook.com) for certificate transparency search", ""),
        ("sub_014", "Use Google dorking: site:target.com -www to find subdomains", ""),
        ("sub_015", "Use Bing dorking: site:target.com for additional subdomain results", ""),
        ("sub_016", "Use Yahoo and DuckDuckGo for subdomain search engine diversity", ""),
        ("sub_017", "Perform DNS brute force with dnsrecon or dnscan using wordlists", "dnsrecon"),
        ("sub_018", "Use massdns for fast DNS resolution of discovered subdomains", "massdns"),
        ("sub_019", "Check for wildcard DNS responses to filter false positive subdomains", ""),
        ("sub_020", "Attempt DNS zone transfer (AXFR) on all authoritative nameservers", ""),
        ("sub_021", "Enumerate subdomains from JavaScript files on the main domain", ""),
        ("sub_022", "Extract subdomains from SPF records via include mechanisms", ""),
        ("sub_023", "Extract subdomains from DMARC aggregate reports (rua tag)", ""),
        ("sub_024", "Use Google Transparency Report for certificate search", ""),
        ("sub_025", "Check for subdomain takeover vulnerability on all discovered subdomains", ""),
        ("sub_026", "Verify DNSSEC configuration and look for misconfigurations", ""),
        ("sub_027", "Use nmap DNS brute script for additional subdomain enumeration", "nmap"),
        ("sub_028", "Check for dangling CNAME records pointing to expired services", ""),
        ("sub_029", "Look for internal IP address leaks in DNS records", ""),
        ("sub_030", "Use sublist3r with all search engine modules enabled", "sublist3r"),
        ("sub_031", "Check for subdomains in robots.txt and sitemap.xml files", ""),
        ("sub_032", "Search GitHub/GitLab repositories for subdomain references in code", ""),
        ("sub_033", "Check Stack Overflow and developer forums for subdomain leaks", ""),
        ("sub_034", "Use Chaos dataset from ProjectDiscovery for community subdomains", ""),
        ("sub_035", "Check for subdomains embedded in Android/iOS app APKs/IPAs", ""),
        ("sub_036", "Use Rapid7 Open Data (Project Sonar) for forward DNS lookup", ""),
        ("sub_037", "Enumerate cloud subdomains (AWS S3, Azure Blob, GCP Storage)", ""),
        ("sub_038", "Check for subdomains leaked in email headers (SPF/DKIM/DMARC)", ""),
        ("sub_039", "Use Recon.dev API for subdomain enumeration from recon data", ""),
        ("sub_040", "Check for Punycode/IDN subdomain variants for homograph attacks", ""),
        ("sub_041", "Search for subdomains in Internet Archive Wayback CDX API", ""),
        ("sub_042", "Look for subdomains in technology detection tools (Wappalyzer)", ""),
        ("sub_043", "Use BufferOver.run for subdomain data from Rapid7 Sonar", ""),
        ("sub_044", "Check for subdomains in Common Crawl data index", ""),
        ("sub_045", "Use DNSrecon for SRV record enumeration", "dnsrecon"),
        ("sub_046", "Check for subdomains via HTTP certificate parsing (openssl s_client)", "openssl"),
        ("sub_047", "Use CertSpotter API for certificate transparency monitoring", ""),
        ("sub_048", "Search for subdomains in FOFA search engine", ""),
        ("sub_049", "Check for subdomains in ZoomEye search engine", ""),
        ("sub_050", "Use DorkAssistant for automated Google dork subdomain enumeration", ""),
    ]
    for cid, desc, tool in sub:
        checks.append(CheckItem(check_id=cid, category=C.SUBDOMAIN_ENUM,
                                description=desc, tool_name=tool))

    # ══════════════════════════════════════════════════════════════════════════
    # CATEGORY 2: PORT SCANNING & SERVICE ENUMERATION — 50 checks
    # ══════════════════════════════════════════════════════════════════════════
    port = [
        ("port_001", "Run nmap TCP SYN scan on all 65535 ports for complete coverage", "nmap"),
        ("port_002", "Use masscan for ultra-fast port scanning across large IP ranges", "masscan"),
        ("port_003", "Use rustscan for fast port discovery with automatic nmap integration", "rustscan"),
        ("port_004", "Run nmap UDP scan on common ports (53, 67, 68, 123, 161, 500, 514)", "nmap"),
        ("port_005", "Use nmap service version detection (-sV) on all discovered open ports", "nmap"),
        ("port_006", "Use nmap OS detection (-O) when ICMP is allowed", "nmap"),
        ("port_007", "Run nmap default script scan (-sC) for vulnerability detection scripts", "nmap"),
        ("port_008", "Use unicornscan for asynchronous port scanning with speed benefits", "unicornscan"),
        ("port_009", "Check for services on non-standard ports (HTTP on 8080, 8443, 8000)", ""),
        ("port_010", "Scan for hidden admin ports (10000 Webmin, 20000 Usermin, 30000)", ""),
        ("port_011", "Use naabu for fast port scanning with SYN and CONNECT mode support", "naabu"),
        ("port_012", "Enumerate services behind load balancers with multiple scan passes", ""),
        ("port_013", "Check for IPv6 addresses and run port scans on IPv6 interfaces", ""),
        ("port_014", "Use nmap timing templates (T0-T5) based on stealth requirements", "nmap"),
        ("port_015", "Run nmap with fragmentation and decoy options for IDS evasion", "nmap"),
        ("port_016", "Check for port knocking sequences on filtered ports", ""),
        ("port_017", "Identify proxy services (Squid on 3128, SOCKS on 1080, CCProxy on 808)", ""),
        ("port_018", "Enumerate database ports (3306 MySQL, 5432 PostgreSQL, 1433 MSSQL, 27017 MongoDB)", ""),
        ("port_019", "Check for Redis on port 6379 with unauthenticated access enabled", ""),
        ("port_020", "Check for Elasticsearch on port 9200 with unauthorized read access", ""),
        ("port_021", "Check for Memcached on port 11211 with unauthenticated access", ""),
        ("port_022", "Scan for Docker API on port 2375/2376 for unauthenticated access", ""),
        ("port_023", "Scan for Kubernetes API on port 6443/8443 for cluster access", ""),
        ("port_024", "Check for RDP on port 3389 with weak or no NLA enforcement", ""),
        ("port_025", "Check for SSH on port 22 and non-standard ports with default creds", ""),
        ("port_026", "Check for FTP on port 21 with anonymous login enabled", ""),
        ("port_027", "Check for SMTP on port 25 for open relay misconfiguration", ""),
        ("port_028", "Check for SNMP on port 161 with default community strings (public/private)", ""),
        ("port_029", "Identify load balancers (F5, HAProxy, Nginx) via server headers", ""),
        ("port_030", "Check for VNC on port 5900+ without authentication requirement", ""),
        ("port_031", "Enumerate RPC services on port 111 with rpcinfo", "rpcinfo"),
        ("port_032", "Check for WebDAV on common ports for file management access", ""),
        ("port_033", "Scan for Jenkins on port 8080/8443 for CI/CD access", ""),
        ("port_034", "Check for GitLab on port 80/443/8080 for repository access", ""),
        ("port_035", "Look for Jupyter notebooks on port 8888 with no authentication", ""),
        ("port_036", "Check for Spark UI on port 4040/8080/8081 for cluster info", ""),
        ("port_037", "Enumerate Hadoop services on ports 50070/8088/19888 for big data", ""),
        ("port_038", "Check for Consul on port 8500 for service discovery access", ""),
        ("port_039", "Check for etcd on port 2379 for key-value store access", ""),
        ("port_040", "Check for ZooKeeper on port 2181 for distributed coordination access", ""),
        ("port_041", "Check for Apache Kafka on port 9092 for message broker access", ""),
        ("port_042", "Check for RabbitMQ on port 5672/15672 for message queue access", ""),
        ("port_043", "Check for ActiveMQ on port 61616/8161 for JMS access", ""),
        ("port_044", "Check for Nagios on port 5666/80 for monitoring dashboard access", ""),
        ("port_045", "Check for Zabbix on port 10050/10051 for monitoring access", ""),
        ("port_046", "Check for Puppet on port 8140 for configuration management access", ""),
        ("port_047", "Check for Ansible Tower on port 443 for automation access", ""),
        ("port_048", "Check for TeamCity on port 8111 for CI/CD access", ""),
        ("port_049", "Check for Bamboo on port 8085 for CI/CD access", ""),
        ("port_050", "Check for SonarQube on port 9000 for code quality dashboard access", ""),
    ]
    for cid, desc, tool in port:
        checks.append(CheckItem(check_id=cid, category=C.PORT_SCAN,
                                description=desc, tool_name=tool))

    # ══════════════════════════════════════════════════════════════════════════
    # CATEGORY 3: TECHNOLOGY FINGERPRINTING — 40 checks
    # ══════════════════════════════════════════════════════════════════════════
    tech = [
        ("tech_001", "Use Wappalyzer browser extension for technology stack detection", ""),
        ("tech_002", "Use whatweb for command-line technology fingerprinting at scale", "whatweb"),
        ("tech_003", "Use webanalyze (Go-based Wappalyzer) for fast batch fingerprinting", "webanalyze"),
        ("tech_004", "Check HTTP response headers for server version disclosure (Server, X-Powered-By)", ""),
        ("tech_005", "Check X-Powered-By header for backend technology identification", ""),
        ("tech_006", "Analyze cookies for framework indicators (PHPSESSID, JSESSIONID, ASP.NET_SessionId)", ""),
        ("tech_007", "Check for framework-specific meta tags and generator tags in HTML", ""),
        ("tech_008", "Identify CMS using WPScan (WordPress), Joomscan (Joomla), Droopescan (Drupal)", "wpscan"),
        ("tech_009", "Detect JavaScript frameworks via source code analysis (React, Angular, Vue)", ""),
        ("tech_010", "Check for React indicators (__NEXT_DATA__, _reactRootContainer)", ""),
        ("tech_011", "Check for Angular indicators (ng-version, ng-app, _nghost)", ""),
        ("tech_012", "Check for Vue.js indicators (__vue__, data-v- attributes)", ""),
        ("tech_013", "Identify backend language from error messages and file extensions", ""),
        ("tech_014", "Check for Cloudflare CDN via cf-ray headers and DNS resolution", ""),
        ("tech_015", "Identify hosting provider from IP WHOIS data and ASN lookup", ""),
        ("tech_016", "Use BuiltWith API for detailed technology profiling and history", ""),
        ("tech_017", "Check for WAF using wafw00f or wappalyzer WAF detection", "wafw00f"),
        ("tech_018", "Identify CDN provider via CNAME records (cdn, edge, cloudfront)", ""),
        ("tech_019", "Check for specific CMS version via readme.html, changelog files", ""),
        ("tech_020", "Use fingerprintx for service fingerprinting on open ports", "fingerprintx"),
        ("tech_021", "Detect API gateway from response headers (X-Request-ID, X-Amzn-Trace)", ""),
        ("tech_022", "Identify GraphQL endpoint via introspection query", ""),
        ("tech_023", "Check for Swagger/OpenAPI documentation at /swagger-ui/, /api-docs/", ""),
        ("tech_024", "Detect GraphQL Playground or GraphiQL interface at /graphql", ""),
        ("tech_025", "Check for WordPress REST API at /wp-json/wp/v2/", ""),
        ("tech_026", "Identify Laravel via /telescope, /_debugbar, /horizon endpoints", ""),
        ("tech_027", "Check for Django admin at /admin/ or /django-admin/ login panel", ""),
        ("tech_028", "Detect Rails via specific cookie naming (app_session) and headers", ""),
        ("tech_029", "Check for Spring Boot actuator endpoints (/actuator/health, /actuator/env)", ""),
        ("tech_030", "Identify ASP.NET via viewstate and event validation hidden fields", ""),
        ("tech_031", "Check for PHP via X-Powered-By: PHP header and .php extensions", ""),
        ("tech_032", "Detect Node.js via X-Powered-By: Express header", ""),
        ("tech_033", "Check for Next.js via __NEXT_DATA__ script tag and build ID", ""),
        ("tech_034", "Check for Nuxt.js via __NUXT__ script tag and data attributes", ""),
        ("tech_035", "Identify Gatsby via gatsby-script and ___graphql endpoint", ""),
        ("tech_036", "Check for Svelte via class:svelte-xxx data attributes", ""),
        ("tech_037", "Detect Ember.js via meta name=ember-cli and script tags", ""),
        ("tech_038", "Check for Meteor via __meteor_runtime_config__ script", ""),
        ("tech_039", "Identify Flask via specific cookie naming and Werkzeug headers", ""),
        ("tech_040", "Detect FastAPI via /docs (Swagger UI) and /redoc endpoints", ""),
    ]
    for cid, desc, tool in tech:
        checks.append(CheckItem(check_id=cid, category=C.TECH_FINGERPRINT,
                                description=desc, tool_name=tool))

    # ══════════════════════════════════════════════════════════════════════════
    # CATEGORY 4: CONTENT & URL DISCOVERY — 50 checks
    # ══════════════════════════════════════════════════════════════════════════
    content = [
        ("cont_001", "Use ffuf for fast directory and file fuzzing with recursive mode", "ffuf"),
        ("cont_002", "Use gobuster for directory/file brute forcing with multiple threads", "gobuster"),
        ("cont_003", "Use dirsearch for recursive directory scanning with extensions", "dirsearch"),
        ("cont_004", "Use feroxbuster for recursive content discovery with smart filtering", "feroxbuster"),
        ("cont_005", "Check for robots.txt and analyze all disallowed entries for hidden paths", ""),
        ("cont_006", "Check for sitemap.xml for hidden URLs and site structure information", ""),
        ("cont_007", "Check for .well-known/ directory (security.txt, assetlinks.json, change-password)", ""),
        ("cont_008", "Look for backup files (.bak, .old, .orig, .save, .swp, .tmp)", ""),
        ("cont_009", "Check for configuration files (.env, .htaccess, .htpasswd, web.config, app.config)", ""),
        ("cont_010", "Look for source code repositories (.git, .svn, .hg, .bzr directories)", ""),
        ("cont_011", "Check for exposed .git directory (HEAD, config, index, objects)", ""),
        ("cont_012", "Search for .DS_Store files for macOS directory listing information", ""),
        ("cont_013", "Check for WP-config.php, config.php, database.yml, settings.py exposure", ""),
        ("cont_014", "Look for backup archives (.zip, .tar.gz, .rar, .7z, .bak.zip)", ""),
        ("cont_015", "Search for log files (error.log, access.log, debug.log, application.log)", ""),
        ("cont_016", "Check for debug endpoints (/debug, /trace, /status, /healthz, /info)", ""),
        ("cont_017", "Look for test files (test.php, test.html, info.php, phpinfo.php)", ""),
        ("cont_018", "Check for API documentation (/api-docs, /swagger, /redoc, /graphql)", ""),
        ("cont_019", "Look for admin panels (/admin, /administrator, /manager, /cpanel, /backend)", ""),
        ("cont_020", "Check for phpMyAdmin (/phpmyadmin, /pma, /dbadmin, /mysql)", ""),
        ("cont_021", "Look for CMS admin (/wp-admin, /wp-login.php, /administrator/index.php)", ""),
        ("cont_022", "Check for staging/dev environments on subdomains (dev., staging., test.)", ""),
        ("cont_023", "Search for publicly accessible Google Docs/Sheets with sensitive data", ""),
        ("cont_024", "Use waybackurls for historical URL discovery from Wayback Machine", "waybackurls"),
        ("cont_025", "Use gau for fetching URLs from AlienVault, Wayback, Common Crawl", "gau"),
        ("cont_026", "Extract all URLs and endpoints from JavaScript files systematically", ""),
        ("cont_027", "Check for .env file exposure with database credentials and API keys", ""),
        ("cont_028", "Look for docker-compose.yml and Dockerfile exposure in root directory", ""),
        ("cont_029", "Check for package.json, composer.json, requirements.txt exposure", ""),
        ("cont_030", "Search for .htpasswd files with credential exposure", ""),
        ("cont_031", "Look for database dump files (.sql, .db, .sqlite, .mdb)", ""),
        ("cont_032", "Check for Jenkins script console access at /script endpoint", ""),
        ("cont_033", "Look for exposed Grafana dashboards at /grafana/ or :3000", ""),
        ("cont_034", "Check for Prometheus metrics endpoint at /metrics", ""),
        ("cont_035", "Look for Kibana dashboard on port 5601 with no auth", ""),
        ("cont_036", "Check for Airflow web UI on port 8080 with DAG access", ""),
        ("cont_037", "Look for RabbitMQ management on port 15672 with default creds", ""),
        ("cont_038", "Check for Solr admin on port 8983 with core access", ""),
        ("cont_039", "Look for MinIO console on port 9001 with bucket listing", ""),
        ("cont_040", "Check for Apache Tomcat manager at /manager/html", ""),
        ("cont_041", "Look for JBoss admin console at /admin-console/", ""),
        ("cont_042", "Check for WebLogic admin at /console/ with default creds", ""),
        ("cont_043", "Look for IBM WebSphere admin at /ibm/console/", ""),
        ("cont_044", "Check for Confluence admin at /admin/ with default credentials", ""),
        ("cont_045", "Look for Jira admin at /secure/admin/ with default credentials", ""),
        ("cont_046", "Check for exposed .well-known/openid-configuration", ""),
        ("cont_047", "Look for .well-known/oauth-authorization-server", ""),
        ("cont_048", "Check for .well-known/assetlinks.json for Android app linking", ""),
        ("cont_049", "Look for .well-known/apple-app-site-association for iOS universal links", ""),
        ("cont_050", "Check for .well-known/security.txt for security contact information", ""),
    ]
    for cid, desc, tool in content:
        checks.append(CheckItem(check_id=cid, category=C.CONTENT_DISCOVERY,
                                description=desc, tool_name=tool))

    # ══════════════════════════════════════════════════════════════════════════
    # CATEGORY 5: LINK & PARAMETER DISCOVERY — 40 checks
    # ══════════════════════════════════════════════════════════════════════════
    link = [
        ("link_001", "Use katana for comprehensive web crawling and URL discovery", "katana"),
        ("link_002", "Use hakrawler for fast web crawling with depth control", "hakrawler"),
        ("link_003", "Use Burp Suite spider for comprehensive site mapping", ""),
        ("link_004", "Extract all links from JavaScript files using LinkFinder tool", "linkfinder"),
        ("link_005", "Extract API endpoints from JS files using JSParser analysis", ""),
        ("link_006", "Use paramspider for parameter discovery from historical data", "paramspider"),
        ("link_007", "Find hidden parameters with arjun for HTTP parameter discovery", "arjun"),
        ("link_008", "Check for path-based parameters in URL paths", ""),
        ("link_009", "Analyze JavaScript for API routes and hidden parameters", ""),
        ("link_010", "Check for URL fragments and hash-based routing (#/path)", ""),
        ("link_011", "Discover WebSocket endpoints and real-time connections", ""),
        ("link_012", "Look for Server-Sent Events (SSE) endpoints for streaming data", ""),
        ("link_013", "Find polling endpoints and long-polling connections for real-time", ""),
        ("link_014", "Check for microservices architecture with multiple API gateways", ""),
        ("link_015", "Discover internal API documentation in JS source map files", ""),
        ("link_016", "Extract variables and constants from minified JavaScript", ""),
        ("link_017", "Check for sourcemap files (.map) for original source code access", ""),
        ("link_018", "Analyze Angular/React/Vue compiled templates for route definitions", ""),
        ("link_019", "Check for REST API versioning (/v1/, /v2/, /v3/)", ""),
        ("link_020", "Look for GraphQL schema via introspection queries", ""),
        ("link_021", "Discover SOAP WSDL endpoints (?wsdl, ?WSDL, ?xsd)", ""),
        ("link_022", "Check for XML-RPC endpoints (/xmlrpc.php)", ""),
        ("link_023", "Find form action URLs and hidden form field parameters", ""),
        ("link_024", "Analyze AJAX calls in browser developer tools network tab", ""),
        ("link_025", "Check for iframe and embed source URLs for cross-origin content", ""),
        ("link_026", "Discover image/asset CDN URLs for additional attack surface", ""),
        ("link_027", "Look for OAuth/OpenID configuration endpoints at /.well-known/", ""),
        ("link_028", "Check for SAML metadata endpoints for federation config", ""),
        ("link_029", "Find callback/redirect URLs in authentication flows", ""),
        ("link_030", "Analyze postMessage handlers for cross-origin communication", ""),
        ("link_031", "Check for URL parameters in Referer headers of outgoing links", ""),
        ("link_032", "Look for email templates with parameterized URLs", ""),
        ("link_033", "Check for webhooks with configurable callback URLs", ""),
        ("link_034", "Discover file upload endpoints and their accepted parameters", ""),
        ("link_035", "Check for export/download endpoints with configurable output", ""),
        ("link_036", "Look for search endpoints with filter/sort parameters", ""),
        ("link_037", "Check for pagination parameters (page, offset, limit, cursor)", ""),
        ("link_038", "Discover batch/bulk operation endpoints", ""),
        ("link_039", "Check for admin/debug endpoints from JS route definitions", ""),
        ("link_040", "Look for WebSocket message format from JS analysis", ""),
    ]
    for cid, desc, tool in link:
        checks.append(CheckItem(check_id=cid, category=C.LINK_PARAM_DISCOVERY,
                                description=desc, tool_name=tool))

    return checks


# ── Category metadata ─────────────────────────────────────────────────────────
CATEGORY_INFO = {
    C.SUBDOMAIN_ENUM: {
        "name": "Subdomain Enumeration",
        "icon": "🌐",
        "total": 50,
        "description": "Discover all subdomains and DNS assets related to the target",
    },
    C.PORT_SCAN: {
        "name": "Port Scanning & Service Enumeration",
        "icon": "🔌",
        "total": 50,
        "description": "Scan for open ports, identify running services and their versions",
    },
    C.TECH_FINGERPRINT: {
        "name": "Technology Fingerprinting",
        "icon": "🔍",
        "total": 40,
        "description": "Identify web technologies, frameworks, CDNs, and WAFs",
    },
    C.CONTENT_DISCOVERY: {
        "name": "Content & URL Discovery",
        "icon": "📁",
        "total": 50,
        "description": "Find hidden files, directories, endpoints, and sensitive data",
    },
    C.LINK_PARAM_DISCOVERY: {
        "name": "Link & Parameter Discovery",
        "icon": "🔗",
        "total": 40,
        "description": "Extract links, parameters, APIs, and JS endpoints",
    },
}

TOTAL_CHECKS = 230
