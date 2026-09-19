"""
bb_harness.core.config
Global configuration, API key management, path resolution, and runtime settings.
"""
import os
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent.parent  # bb-harness/
DATA_DIR = BASE_DIR / "data"
WORDLIST_DIR = DATA_DIR / "wordlists"
OUTPUT_DIR = BASE_DIR / "output"
REPORTS_DIR = OUTPUT_DIR / "reports"
DB_PATH = DATA_DIR / "bb_harness.db"

for d in [DATA_DIR, WORDLIST_DIR, OUTPUT_DIR, REPORTS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# ── Docker ─────────────────────────────────────────────────────────────────────
DOCKER_IMAGE = "bb-harness:latest"
CONTAINER_WORKSPACE = "/workspace"


@dataclass
class APIKeys:
    """API keys loaded from env or .env file."""
    shodan: str = ""
    securitytrails: str = ""
    virustotal: str = ""
    censys_id: str = ""
    censys_secret: str = ""
    github_token: str = ""
    chaos: str = ""             # ProjectDiscovery Chaos
    builtwith: str = ""
    whoxy: str = ""
    hunter: str = ""
    fofa_email: str = ""
    fofa_key: str = ""
    zoomeye: str = ""
    recon_dev: str = ""

    @classmethod
    def from_env(cls) -> "APIKeys":
        return cls(
            shodan=os.getenv("SHODAN_API_KEY", ""),
            securitytrails=os.getenv("SECURITYTRAILS_API_KEY", ""),
            virustotal=os.getenv("VIRUSTOTAL_API_KEY") or os.getenv("VT_API_KEY", ""),
            censys_id=os.getenv("CENSYS_API_ID", ""),
            censys_secret=os.getenv("CENSYS_API_SECRET", ""),
            github_token=os.getenv("GITHUB_TOKEN", ""),
            chaos=os.getenv("CHAOS_API_KEY", ""),
            builtwith=os.getenv("BUILTWITH_API_KEY", ""),
            whoxy=os.getenv("WHOXY_API_KEY", ""),
            hunter=os.getenv("HUNTER_API_KEY", ""),
            fofa_email=os.getenv("FOFA_EMAIL", ""),
            fofa_key=os.getenv("FOFA_KEY", ""),
            zoomeye=os.getenv("ZOOMEYE_API_KEY", ""),
            recon_dev=os.getenv("RECON_DEV_API_KEY", ""),
        )


@dataclass
class ScanConfig:
    """Runtime scan configuration."""
    target: str = ""
    mode: str = "host"          # "host" or "container"
    concurrency: int = 50
    timeout: int = 30           # seconds per request
    dns_resolvers: list = field(default_factory=lambda: [
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
        "9.9.9.9", "208.67.222.222", "208.67.220.220",
    ])
    threads: int = 10
    rate_limit: int = 150       # requests per second
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    wordlist_subdomain: str = ""
    wordlist_content: str = ""
    ports_top: str = "1-65535"
    ports_common: str = "21,22,25,53,67,68,80,110,111,123,135,139,143,161,389,443,445,500,514,587,636,993,995,1080,1433,1521,2049,2181,2375,2376,2379,3128,3306,3389,4040,5432,5555,5666,5672,5900,5901,6379,6443,8000,8080,8081,8085,8088,8111,8140,8161,8443,8500,8888,8983,9000,9001,9092,9200,10000,10050,10051,11211,15672,19888,20000,27017,30000,50070,61616"

    def validate(self):
        if not self.target:
            raise ValueError("No target set. Use /target <domain>")
        return True

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "mode": self.mode,
            "concurrency": self.concurrency,
            "timeout": self.timeout,
            "threads": self.threads,
            "rate_limit": self.rate_limit,
        }


# ── Global singleton ──────────────────────────────────────────────────────────
api_keys = APIKeys.from_env()
scan_config = ScanConfig()
