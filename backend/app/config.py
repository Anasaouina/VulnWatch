import os
from dataclasses import dataclass, field


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name, "")
    try:
        return int(raw) if raw.strip() else default
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    raw = os.environ.get(name, "")
    try:
        return float(raw) if raw.strip() else default
    except ValueError:
        return default


@dataclass
class Settings:
    database_url: str = os.environ.get(
        "DATABASE_URL",
        "postgresql+psycopg://vulnwatch:vulnwatch@localhost:5432/vulnwatch",
    )
    sync_interval_seconds: int = field(
        default_factory=lambda: _int("SYNC_INTERVAL_SECONDS", 3600)
    )
    http_timeout_seconds: float = field(
        default_factory=lambda: _float("HTTP_TIMEOUT_SECONDS", 30)
    )
    http_retries: int = field(default_factory=lambda: _int("HTTP_RETRIES", 3))
    http_retry_backoff_seconds: float = field(
        default_factory=lambda: _float("HTTP_RETRY_BACKOFF_SECONDS", 5)
    )
    cve_now_base_url: str = os.environ.get("CVE_NOW_BASE_URL", "https://cve.now")
    # Max cve.now list pages fetched per collector cycle (30 entries per page).
    cve_now_max_pages_per_run: int = field(
        default_factory=lambda: _int("CVE_NOW_MAX_PAGES_PER_RUN", 4)
    )
    cve_now_page_pause_seconds: float = field(
        default_factory=lambda: _float("CVE_NOW_PAGE_PAUSE_SECONDS", 3)
    )
    cve_now_detail_pause_seconds: float = field(
        default_factory=lambda: _float("CVE_NOW_DETAIL_PAUSE_SECONDS", 3)
    )
    cve_now_max_details_per_run: int = field(
        default_factory=lambda: _int("CVE_NOW_MAX_DETAILS_PER_RUN", 25)
    )
    cisa_kev_url: str = os.environ.get(
        "CISA_KEV_URL",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    )
    # FIRST EPSS bulk daily file (documented at https://www.first.org/epss/data,
    # verified live 2026-11-07: gzip CSV with a #model_version/score_date meta
    # line, one stable URL that always points at the current day's file).
    epss_bulk_url: str = os.environ.get(
        "EPSS_BULK_URL",
        "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
    )
    # Official EPSS API: use for on-demand single-CVE lookups only, never for
    # bulk sync (the daily CSV is the documented bulk mechanism).
    epss_api_url: str = os.environ.get(
        "EPSS_API_URL",
        "https://api.first.org/data/v1/epss",
    )
    # VulnWatch priority thresholds (VulnWatch assessment — not an official
    # FIRST, CISA or CVSS rating). EPSS is the probability of exploitation in
    # the wild within 30 days, so EPSS_HIGH means "better than even odds".
    priority_epss_high: float = field(
        default_factory=lambda: _float("PRIORITY_EPSS_HIGH", 0.5)
    )
    priority_epss_elevated: float = field(
        default_factory=lambda: _float("PRIORITY_EPSS_ELEVATED", 0.1)
    )
    # --- NVD (attributed CVSS + canonical CVE catalog) -----------------------
    nvd_api_url: str = os.environ.get(
        "NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0"
    )
    # Free key (https://nvd.nist.gov/developers/request-an-api-key) raises the
    # rate limit from 5 to 50 requests per 30 s; without one the sync paces
    # itself with NVD_PAGE_PAUSE_SECONDS.
    nvd_api_key: str = os.environ.get("NVD_API_KEY", "")
    nvd_page_pause_seconds: float = field(
        default_factory=lambda: _float("NVD_PAGE_PAUSE_SECONDS", 7)
    )
    nvd_max_pages_per_run: int = field(
        default_factory=lambda: _int("NVD_MAX_PAGES_PER_RUN", 3)
    )
    # --- GitHub Advisory Database (GHSA, public REST) ------------------------
    github_advisory_url: str = os.environ.get(
        "GH_ADV_URL", "https://api.github.com/advisories"
    )
    # Optional token; raises the anonymous 60 req/h limit to 300.
    github_token: str = os.environ.get("GITHUB_TOKEN", "")
    gh_adv_max_pages_per_run: int = field(
        default_factory=lambda: _int("GH_ADV_MAX_PAGES_PER_RUN", 4)
    )
    # --- OSV.dev (GHSA detail enrichment; ids come from github_advisory) -----
    osv_api_url: str = os.environ.get("OSV_API_URL", "https://api.osv.dev/v1/vulns")
    osv_max_per_run: int = field(default_factory=lambda: _int("OSV_MAX_PER_RUN", 30))
    # --- Exploit-DB / Metasploit / Nuclei / PoC-in-GitHub --------------------
    exploit_db_url: str = os.environ.get(
        "EXPLOIT_DB_URL",
        "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
    )
    metasploit_url: str = os.environ.get(
        "METASPLOIT_URL",
        "https://raw.githubusercontent.com/rapid7/metasploit-framework/"
        "master/db/modules_metadata_base.json",
    )
    nuclei_tree_url: str = os.environ.get(
        "NUCLEI_TREE_URL",
        "https://api.github.com/repos/projectdiscovery/nuclei-templates/"
        "git/trees/main?recursive=1",
    )
    poc_base_url: str = os.environ.get(
        "POC_BASE_URL",
        "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master",
    )
    poc_max_per_run: int = field(default_factory=lambda: _int("POC_MAX_PER_RUN", 15))
    # --- Vendor/distro feeds -------------------------------------------------
    redhat_securitydata_url: str = os.environ.get(
        "REDHAT_SECURITYDATA_URL",
        "https://access.redhat.com/hydra/rest/securitydata/cve.json",
    )
    redhat_max_pages_per_run: int = field(
        default_factory=lambda: _int("REDHAT_MAX_PAGES_PER_RUN", 5)
    )
    debian_tracker_url: str = os.environ.get(
        "DEBIAN_TRACKER_URL",
        "https://security-tracker.debian.org/tracker/data/json",
    )
    ubuntu_api_url: str = os.environ.get(
        "UBUNTU_API_URL", "https://cve.ubuntu.com/api/v0/cves/"
    )
    ubuntu_max_pages_per_run: int = field(
        default_factory=lambda: _int("UBUNTU_MAX_PAGES_PER_RUN", 5)
    )
    # --- Context feeds -------------------------------------------------------
    # cisa.gov is Akamai-blocked for some datacenter IPs; point this at a
    # reachable mirror if needed.
    cisa_advisories_url: str = os.environ.get(
        "CISA_ADVISORIES_URL",
        "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    )
    # ThreatFox requires a free Auth-Key from https://auth.abuse.ch/.
    threatfox_api_url: str = os.environ.get(
        "THREATFOX_API_URL", "https://threatfox-api.abuse.ch/api/v1/"
    )
    threatfox_auth_key: str = os.environ.get("THREATFOX_AUTH_KEY", "")
    # Vulners requires an API key (the unauthenticated endpoint is
    # Cloudflare-challenged for datacenter IPs).
    vulners_api_url: str = os.environ.get(
        "VULNERS_API_URL", "https://vulners.com/api/v3/search/id/"
    )
    vulners_api_key: str = os.environ.get("VULNERS_API_KEY", "")
    vulners_max_per_run: int = field(
        default_factory=lambda: _int("VULNERS_MAX_PER_RUN", 20)
    )
    allow_manual_sync: bool = os.environ.get("ALLOW_MANUAL_SYNC", "true") != "false"


settings = Settings()
