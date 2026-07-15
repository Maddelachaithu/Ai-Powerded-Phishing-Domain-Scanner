from datetime import datetime

SUSPICIOUS_PREFIXES = ['login-', 'secure-', 'verify-', 'account-', 'support-', 'my-', 'id-']

def score_domain(result: dict, target_domain: str, scan_time: datetime = None) -> dict:
    """
    Computes a risk score (0-100), risk label, confidence level, and auditable reasons for a domain check result.
    """
    if scan_time is None:
        scan_time = datetime.now()

    score = 0
    reasons = []
    confidence = "full"

    # 1. Registration Date Signals
    reg_date_str = result.get("registered_date")
    if reg_date_str:
        try:
            reg_date = datetime.strptime(reg_date_str, "%Y-%m-%d")
            diff_days = (scan_time.date() - reg_date.date()).days
            
            if diff_days >= 0:
                if diff_days <= 30:
                    score += 35
                    reasons.append(f"Domain registered {diff_days} days ago (+35)")
                elif diff_days <= 90:
                    score += 20
                    reasons.append(f"Domain registered {diff_days} days ago (+20)")
                elif diff_days > 365:
                    score -= 15
                    reasons.append("Domain registered over 1 year ago (-15)")
        except Exception:
            # Fallback gracefully, don't penalize or break scoring
            pass

    # 2. Suspicious Prefix Signal
    domain_name = result.get("domain", "").lower()
    matched_prefix = None
    for prefix in SUSPICIOUS_PREFIXES:
        if domain_name.startswith(prefix):
            matched_prefix = prefix
            break
            
    if matched_prefix:
        score += 25
        reasons.append(f"Contains phishing-pattern prefix '{matched_prefix}' (+25)")

    # 3. Homoglyph Substitution Signal
    techniques = result.get("techniques", [])
    if "homoglyph" in techniques:
        score += 20
        reasons.append("Homoglyph substitution used (+20)")

    # 4. Character Substitution/Transposition Signal
    char_techniques = {"omission", "duplication", "adjacent-key", "transposition"}
    if any(t in techniques for t in char_techniques):
        score += 15
        reasons.append("Character-substitution/transposition (+15)")

    # 5. TLD Swap Only Signal (rest of name identical)
    # Checks if 'tld_swap' is the only technique that was used to generate it
    if set(techniques) == {"tld_swap"}:
        score += 5
        reasons.append("TLD swap only (+5)")

    # 6. Both DNS-live AND Certificate Confirmed Signal
    dns_resolves = result.get("dns_resolves", False)
    cert_status = result.get("certificate_status", "unknown")
    
    if dns_resolves and cert_status == "confirmed":
        score += 15
        reasons.append("Both DNS-live and certificate confirmed (+15)")

    # 7. Certificate Check returned "unknown" (crt.sh failed)
    if cert_status == "unknown":
        confidence = "reduced"

    # Clamp the final score between 0 and 100
    score = max(0, min(score, 100))

    # Risk Label Mapping
    if score <= 39:
        label = "LOW"
    elif score <= 69:
        label = "MEDIUM"
    else:
        label = "HIGH"

    # Return copy with computed scores and metadata
    scored_result = dict(result)
    scored_result.update({
        "risk_score": score,
        "risk_label": label,
        "confidence": confidence,
        "reasons": reasons
    })
    
    return scored_result
