"""VulnWatch priority classification tests (see app/priority.py for rules)."""

from app.priority import compute_priority


def _p(**kwargs):
    base = dict(
        cvss_score=None,
        stated_severity=None,
        epss_score=None,
        is_kev=False,
        high_threshold=0.5,
        elevated_threshold=0.1,
    )
    base.update(kwargs)
    return compute_priority(**base)


def test_kev_is_always_urgent():
    prio, reasons = _p(is_kev=True, epss_score=0.001, cvss_score=2.0)
    assert prio == "urgent"
    assert "CISA" in reasons[0] and "Known Exploited" in reasons[0]


def test_high_epss_plus_high_impact_is_high():
    prio, reasons = _p(cvss_score=9.8, epss_score=0.6)
    assert prio == "high"
    assert any("high threshold" in r for r in reasons)


def test_high_epss_low_impact_is_medium():
    prio, reasons = _p(cvss_score=5.0, epss_score=0.6)
    assert prio == "medium"
    assert any("lower impact" in r for r in reasons)


def test_elevated_epss_high_impact_is_medium():
    prio, reasons = _p(cvss_score=8.8, epss_score=0.12)
    assert prio == "medium"
    assert any("elevated" in r for r in reasons)


def test_low_when_no_threshold_crossed():
    prio, _ = _p(cvss_score=5.0, epss_score=0.05)
    assert prio == "low"


def test_stated_severity_counts_as_impact():
    prio, _ = _p(stated_severity="critical", epss_score=0.2)
    assert prio == "medium"
    prio, _ = _p(stated_severity="critical", epss_score=0.6)
    assert prio == "high"


def test_unknown_when_no_signals():
    prio, reasons = _p()
    assert prio == "unknown"
    assert reasons == []


def test_thresholds_are_configurable():
    prio, _ = _p(cvss_score=9.8, epss_score=0.3, high_threshold=0.25)
    assert prio == "high"
    prio, _ = _p(cvss_score=9.8, epss_score=0.3, high_threshold=0.5)
    assert prio == "medium"
    prio, _ = _p(cvss_score=8.0, epss_score=0.05, elevated_threshold=0.04)
    assert prio == "medium"
    # elevated EPSS alone does not escalate when impact is low
    prio, _ = _p(cvss_score=1.0, epss_score=0.05, elevated_threshold=0.04)
    assert prio == "low"


def test_no_epss_but_critical_impact_stays_low():
    # impact alone without an exploitation signal must not be urgent/high
    prio, _ = _p(cvss_score=9.8)
    assert prio == "low"
    prio, _ = _p(stated_severity="critical")
    assert prio == "low"


def test_priority_note_labeling():
    from app.priority import priority_reason_preamble

    assert "VulnWatch assessment" in priority_reason_preamble()
    assert "not an official" in priority_reason_preamble()
