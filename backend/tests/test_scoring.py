from datetime import datetime, timedelta
from backend.scoring import score_domain

def test_scoring_registration_recency():
    scan_time = datetime(2026, 7, 15)
    
    # 1. Registered within last 30 days (+35)
    res_recent = {
        "domain": "examplebank.net",
        "dns_resolves": False,
        "certificate_status": "not_found",
        "registered_date": "2026-07-05",  # 10 days ago
        "registrar": "GoDaddy",
        "techniques": ["tld_swap"]
    }
    # TLD swap only (+5) + recent 30 days (+35) = 40 (MEDIUM)
    scored = score_domain(res_recent, "examplebank.com", scan_time=scan_time)
    assert scored["risk_score"] == 40
    assert scored["risk_label"] == "MEDIUM"
    assert "Domain registered 10 days ago (+35)" in scored["reasons"]

    # 2. Registered within last 90 days, but not 30 (+20)
    res_medium = {
        "domain": "examplebank.net",
        "dns_resolves": False,
        "certificate_status": "not_found",
        "registered_date": "2026-05-16",  # 60 days ago
        "registrar": "GoDaddy",
        "techniques": ["tld_swap"]
    }
    # TLD swap only (+5) + 31-90 days (+20) = 25 (LOW)
    scored = score_domain(res_medium, "examplebank.com", scan_time=scan_time)
    assert scored["risk_score"] == 25
    assert scored["risk_label"] == "LOW"
    assert "Domain registered 60 days ago (+20)" in scored["reasons"]

    # 3. Registered over 1 year ago (-15)
    res_old = {
        "domain": "examplebank.net",
        "dns_resolves": False,
        "certificate_status": "not_found",
        "registered_date": "2025-05-15",  # > 1 year ago
        "registrar": "GoDaddy",
        "techniques": ["tld_swap"]
    }
    # TLD swap only (+5) - 1 year (-15) = -10 (clamped to 0, LOW)
    scored = score_domain(res_old, "examplebank.com", scan_time=scan_time)
    assert scored["risk_score"] == 0
    assert scored["risk_label"] == "LOW"
    assert "Domain registered over 1 year ago (-15)" in scored["reasons"]

def test_scoring_pattern_matches():
    scan_time = datetime(2026, 7, 15)

    # Suspicious prefix (+25)
    res = {
        "domain": "login-examplebank.com",
        "dns_resolves": False,
        "certificate_status": "not_found",
        "registered_date": None,
        "registrar": None,
        "techniques": ["prefix"]
    }
    scored = score_domain(res, "examplebank.com", scan_time=scan_time)
    assert scored["risk_score"] == 25
    assert "Contains phishing-pattern prefix 'login-' (+25)" in scored["reasons"]

    # Homoglyph substitution (+20)
    res = {
        "domain": "ex@mplebank.com",
        "dns_resolves": False,
        "certificate_status": "not_found",
        "registered_date": None,
        "registrar": None,
        "techniques": ["homoglyph"]
    }
    scored = score_domain(res, "examplebank.com", scan_time=scan_time)
    assert scored["risk_score"] == 20
    assert "Homoglyph substitution used (+20)" in scored["reasons"]

    # Character-substitution/transposition (+15)
    res = {
        "domain": "exmaplebank.com",
        "dns_resolves": False,
        "certificate_status": "not_found",
        "registered_date": None,
        "registrar": None,
        "techniques": ["transposition"]
    }
    scored = score_domain(res, "examplebank.com", scan_time=scan_time)
    assert scored["risk_score"] == 15
    assert "Character-substitution/transposition (+15)" in scored["reasons"]

def test_scoring_live_signals_and_confidence():
    scan_time = datetime(2026, 7, 15)

    # DNS resolves AND cert confirmed (+15)
    res = {
        "domain": "examplebank.co",
        "dns_resolves": True,
        "certificate_status": "confirmed",
        "registered_date": None,
        "registrar": None,
        "techniques": ["tld_swap"]
    }
    # TLD swap only (+5) + both live (+15) = 20
    scored = score_domain(res, "examplebank.com", scan_time=scan_time)
    assert scored["risk_score"] == 20
    assert scored["confidence"] == "full"
    assert "Both DNS-live and certificate confirmed (+15)" in scored["reasons"]

    # Cert check unknown -> confidence reduced
    res = {
        "domain": "examplebank.co",
        "dns_resolves": True,
        "certificate_status": "unknown",
        "registered_date": None,
        "registrar": None,
        "techniques": ["tld_swap"]
    }
    scored = score_domain(res, "examplebank.com", scan_time=scan_time)
    assert scored["confidence"] == "reduced"

def test_scoring_clamping_and_labeling():
    scan_time = datetime(2026, 7, 15)

    # High score combination:
    # recent 10 days (+35), prefix (+25), homoglyph (+20), both live (+15)
    # 35 + 25 + 20 + 15 = 95 (HIGH)
    res = {
        "domain": "login-ex@mplebank.com",
        "dns_resolves": True,
        "certificate_status": "confirmed",
        "registered_date": "2026-07-05",
        "registrar": "GoDaddy",
        "techniques": ["prefix", "homoglyph"]
    }
    scored = score_domain(res, "examplebank.com", scan_time=scan_time)
    assert scored["risk_score"] == 95
    assert scored["risk_label"] == "HIGH"
