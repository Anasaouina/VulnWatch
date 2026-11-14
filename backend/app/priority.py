"""VulnWatch priority classification.

This is a VulnWatch assessment — NOT an official FIRST, CISA or CVSS rating.
It combines three independent, individually visible signals:

- CVSS severity (impact-based, static; VulnWatch uses the best attributed
  numeric CVSS score, falling back to a vendor-stated severity label).
- EPSS (probability-based, dynamic: likelihood of exploitation in the wild
  within 30 days). EPSS is a statistical estimate from FIRST, not a
  guarantee that exploitation will or did occur.
- CISA KEV (evidence-based: the CVE is listed in the catalog of vulnerabilities
  that CISA has confirmed were exploited in the wild, based on authoritative
  reporting). KEV is not an exhaustive list of all exploited vulnerabilities.

Rules (configurable via PRIORITY_EPSS_HIGH / PRIORITY_EPSS_ELEVATED):

  urgent  — the CVE is listed in the CISA KEV catalog.
  high    — not in KEV, but EPSS >= PRIORITY_EPSS_HIGH (0.5 by default: better
            than even odds of exploitation in 30 days) AND numeric CVSS >= 7.0
            (High/Critical impact) or a stated High/Critical label.
  medium  — elevated exploitation likelihood combined with lower impact
            (EPSS >= HIGH with CVSS < 7.0), or meaningful likelihood plus High
            impact (EPSS >= ELEVATED = 0.1 with CVSS >= 7.0).
  low     — all remaining cases where at least one numeric signal exists or a
            stated severity label is present.
  unknown — neither CVSS (numeric or stated) nor EPSS is available.

Limits, stated plainly:
- Priority is relative ranking guidance, not a measurement or a substitute for
  an organization's own risk decisions.
- It knows nothing about the user's assets: a high priority never implies a
  CVE affects a system the user actually runs, and asset exposure requires an
  asset inventory with version matching (see watchlist matches for a rough
  keyword/structured approximation).
- KEV only covers confirmed, CISA-catalogued exploitation; absence from KEV
  is not evidence of absence of exploitation.
- EPSS models change over time (see model_version in the history rows), so
  scores across a model-version boundary are not directly comparable.
"""

import logging

log = logging.getLogger("vulnwatch.priority")

PRIORITY_LABELS = ("urgent", "high", "medium", "low", "unknown")
# greater = more urgent; used by the API for sorting and client styling
PRIORITY_RANK = {"urgent": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}

_GENERIC_REASON = (
    "VulnWatch assessment based on CVSS severity, FIRST EPSS exploitation "
    "likelihood and CISA KEV listing; not an official FIRST, CISA or CVSS "
    "rating, and not proof that a system you run is affected."
)


def compute_priority(
    *,
    cvss_score: float | None,
    stated_severity: str | None,
    epss_score: float | None,
    is_kev: bool,
    high_threshold: float,
    elevated_threshold: float,
) -> tuple[str, list[str]]:
    """Return (priority_label, reasons) for the given signals."""
    reasons: list[str] = []
    if is_kev:
        reasons.append(
            "Listed in the CISA Known Exploited Vulnerabilities catalog "
            "(confirmed known exploitation in the wild)."
        )
        return "urgent", reasons

    if cvss_score is None and stated_severity is None and epss_score is None:
        return "unknown", []

    if cvss_score is not None:
        reasons.append(f"CVSS {cvss_score}")
    elif stated_severity:
        reasons.append(f"Source-stated severity: {stated_severity}")
    if epss_score is not None:
        reasons.append(
            f"FIRST EPSS {epss_score:.3f} — estimated probability of "
            "exploitation within the next 30 days"
        )

    if epss_score is not None and epss_score >= high_threshold:
        if _impact_high(cvss_score, stated_severity):
            reasons.append(
                f"EPSS at or above the high threshold ({high_threshold}) with "
                "High/Critical impact severity."
            )
            return "high", reasons
        reasons.append(
            f"EPSS at or above the high threshold ({high_threshold}) but lower "
            "impact severity."
        )
        return "medium", reasons

    if (
        epss_score is not None
        and epss_score >= elevated_threshold
        and _impact_high(cvss_score, stated_severity)
    ):
        reasons.append(
            f"EPSS at or above the elevated threshold ({elevated_threshold}) "
            "with High/Critical impact severity."
        )
        return "medium", reasons

    if epss_score is not None or cvss_score is not None or stated_severity:
        reasons.append("No immediate exploitation-signal threshold met.")
        return "low", reasons
    return "unknown", []


def _impact_high(cvss_score: float | None, stated_severity: str | None) -> bool:
    if cvss_score is not None:
        return cvss_score >= 7.0
    if stated_severity:
        return stated_severity.strip().lower() in ("critical", "high")
    # no impact data: the EPSS thresholds alone cannot establish
    # High/Critical impact, so elevated EPSS does not escalate above medium
    return False


def priority_reason_preamble() -> str:
    return _GENERIC_REASON
