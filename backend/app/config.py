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
    allow_manual_sync: bool = os.environ.get("ALLOW_MANUAL_SYNC", "true") != "false"


settings = Settings()
