"""Scoped Google-dork generation adapted from the supplied dork runner."""
from __future__ import annotations

from urllib.parse import quote


DORK_CATEGORIES = {
    "credentials": [
        'site:{target} ext:env', 'site:{target} ext:env "DB_PASSWORD"',
        'site:{target} ext:env "API_KEY"', 'site:{target} "api_key" OR "apikey"',
        'site:{target} "secret_key" OR "SECRET_KEY"', 'site:{target} "password" filetype:log',
        'site:{target} "password" filetype:txt', 'site:{target} ext:yaml "password:"',
        'site:{target} ext:json "private_key"', 'site:{target} inurl:".git/config"',
        'site:{target} ext:pem "BEGIN RSA PRIVATE KEY"', 'site:{target} "aws_secret_access_key"',
        'site:{target} "AKIA" intext:AKIA', 'site:{target} ext:json "type: service_account"',
    ],
    "pii": [
        'site:{target} ext:csv intext:"email" intext:"phone"',
        'site:{target} ext:xls intext:"ssn"', 'site:{target} ext:xlsx intext:"date of birth"',
        'site:{target} ext:csv "first name" "last name" "email"',
        'site:{target} filetype:csv "password" "username"',
        'site:{target} intitle:"index of" "users.csv"', 'site:{target} intitle:"index of" "customers.csv"',
        'site:{target} ext:log intext:"email"', 'site:{target} filetype:xls "employee" "salary"',
    ],
    "admin": [
        'site:{target} inurl:admin', 'site:{target} inurl:/admin/login',
        'site:{target} inurl:/phpmyadmin', 'site:{target} inurl:/jenkins',
        'site:{target} inurl:/grafana', 'site:{target} inurl:/kibana',
        'site:{target} inurl:/actuator', 'site:{target} inurl:/swagger-ui',
        'site:{target} inurl:/api-docs', 'site:{target} intitle:"admin panel"',
        'site:{target} intitle:"control panel"', 'site:{target} inurl:"/wp-login.php"',
    ],
    "errors": [
        'site:{target} "SQL syntax" OR "mysql_fetch"', 'site:{target} "Warning: mysql_"',
        'site:{target} "Fatal error:" filetype:php', 'site:{target} "Stack trace:" filetype:html',
        'site:{target} "Traceback (most recent call last)"', 'site:{target} "NullPointerException"',
        'site:{target} "DEBUG = True" filetype:py', 'site:{target} "APP_DEBUG=true" ext:env',
        'site:{target} inurl:phpinfo.php', 'site:{target} ext:log "error"',
        'site:{target} intitle:"index of" "error.log"',
    ],
    "cloud": [
        '"{target}" site:s3.amazonaws.com', '"{target}" site:blob.core.windows.net',
        '"{target}" site:storage.googleapis.com', '"{target}" site:firebaseio.com',
        '{target}.s3.amazonaws.com', 'intitle:"index of" site:{target}',
    ],
    "subdomains": [
        'site:*.{target}', 'site:*.*.{target}', 'site:*.{target} inurl:login',
        'site:*.{target} inurl:admin', 'site:*.{target} inurl:api',
        'site:*.{target} inurl:staging', 'site:*.{target} inurl:dev', 'site:*.{target} inurl:test',
    ],
    "params": [
        'site:{target} inurl:url=http', 'site:{target} inurl:redirect=http',
        'site:{target} inurl:next=http', 'site:{target} inurl:?id=',
        'site:{target} inurl:?user_id=', 'site:{target} inurl:search=',
        'site:{target} inurl:q=', 'site:{target} inurl:file=',
        'site:{target} inurl:path=', 'site:{target} inurl:include=',
        'site:{target} inurl:page=', 'site:{target} inurl:debug=',
    ],
    "leaks": [
        'site:pastebin.com "{target}"', 'site:pastebin.com "{target}" "password"',
        'site:github.com "{target}" "password"', 'site:github.com "{target}" "api_key"',
        'site:github.com "{target}" ".env"', 'site:gist.github.com "{target}"',
        'site:notion.so "{target}"', 'site:docs.google.com "{target}"', 'site:trello.com "{target}"',
    ],
    "github": [
        'site:github.com "{target}" "password"', 'site:github.com "{target}" "api_key"',
        'site:github.com "{target}" "secret"', 'site:github.com "{target}" "token"',
        'site:github.com "{target}" extension:env', 'site:github.com "{target}" filename:config.yml',
        'site:github.com "{target}" filename:.env', 'site:github.com "{target}" "BEGIN RSA PRIVATE KEY"',
    ],
    "juicy": [
        'site:{target} intitle:"index of" "backup"', 'site:{target} intitle:"index of" "sql"',
        'site:{target} intitle:"index of" "dump"', 'site:{target} ext:sql',
        'site:{target} ext:bak', 'site:{target} ext:old', 'site:{target} inurl:backup',
        'site:{target} filetype:pdf "confidential"', 'site:{target} filetype:pdf "internal use only"',
    ],
    "microsoft365": [
        'site:login.microsoftonline.com "{target}"', 'site:outlook.office365.com "{target}"',
        'site:{target} inurl:/.well-known/openid-configuration', 'site:{target} inurl:/_layouts',
        'site:{target} inurl:/sites/', '"{target}" site:onedrive.live.com',
        '"{target}" site:1drv.ms', '"{target}" site:app.powerbi.com',
    ],
    "compliance": [
        'site:{target} filetype:pdf "iso 27001"', 'site:{target} filetype:pdf "soc 2"',
        'site:{target} filetype:pdf "PCI DSS"', 'site:{target} filetype:pdf "vulnerability assessment"',
        'site:{target} filetype:pdf "penetration test"', 'site:{target} filetype:pdf "data protection agreement"',
        'site:{target} filetype:pdf "DPA" "personal data"', 'site:{target} filetype:pdf "non-disclosure"',
        'site:{target} filetype:pdf "runbook"', 'site:{target} filetype:pdf "incident response"',
    ],
}


def generate_dorks(target: str, category: str = "all") -> list[dict[str, str]]:
    """Generate text-friendly dork records without issuing search requests."""
    categories = [category] if category != "all" else list(DORK_CATEGORIES)
    records = []
    for name in categories:
        for template in DORK_CATEGORIES.get(name, []):
            dork = template.replace("{target}", target)
            records.append({
                "category": name,
                "dork": dork,
                "url": f"https://www.google.com/search?q={quote(dork)}&num=50",
            })
    return records


def write_dorks(path, target: str, category: str = "all") -> int:
    records = generate_dorks(target, category)
    with open(path, "w", encoding="utf-8") as handle:
        for record in records:
            handle.write(f"# [{record['category']}]\n")
            handle.write(f"DORK: {record['dork']}\n")
            handle.write(f"URL:  {record['url']}\n\n")
    return len(records)
