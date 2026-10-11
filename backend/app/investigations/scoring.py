from datetime import datetime, timezone
from typing import Any


SCORING_VERSION = "url-risk-v1"
REPUTATION_PROVIDERS = {"virustotal", "cloudflare_url_scanner", "abuseipdb"}
USABLE_STATUSES = {"completed", "no_data"}


def _age_days(value: str | None) -> float | None:
    if not value:
        return None
    try:
        observed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return max(0, (datetime.now(timezone.utc) - observed).total_seconds() / 86400)
    except (TypeError, ValueError):
        return None


def score_results(
    results: list[dict[str, Any]],
    thresholds: tuple[int, int, int] = (25, 50, 75),
) -> dict[str, Any]:
    moderate, high, critical = thresholds
    if not (0 < moderate < high < critical <= 100):
        raise ValueError("Risk thresholds must increase from 1 through 100")
    risk_bands = ((critical, "critical"), (high, "high"), (moderate, "moderate"), (0, "low"))
    contributions: list[dict[str, Any]] = []
    reasons: list[str] = []
    direct_scores: list[int] = []
    context_scores: list[int] = []
    usable = 0
    direct_usable = 0
    benign_direct = 0
    adverse_direct = 0
    fresh = 0

    by_provider = {str(item.get("provider")): item for item in results}
    for provider in REPUTATION_PROVIDERS:
        item = by_provider.get(provider)
        if not item or item.get("status") not in USABLE_STATUSES or item.get("status") == "no_data":
            continue
        assessment = item.get("assessment") or {}
        scope = assessment.get("scope") or item.get("queried_scope")
        verdict = str(assessment.get("verdict") or "unknown")
        if verdict in {"unknown", "not_scored", ""}:
            continue
        usable += 1
        observed_age = _age_days(item.get("observed_at"))
        expired = observed_age is not None and observed_age > int(assessment.get("fresh_days", 30))
        if not expired:
            fresh += 1
        contribution = 0
        direct = scope in {"exact_url", "hostname"}

        if provider == "virustotal":
            metrics = item.get("native_metrics") or {}
            malicious = int(metrics.get("malicious") or 0)
            suspicious = int(metrics.get("suspicious") or 0)
            if direct:
                direct_usable += 1
                if malicious > 0:
                    contribution = min(100, 75 + min(malicious, 10) * 2)
                    adverse_direct += 1
                    reasons.append(f"VirusTotal reports {malicious} malicious and {suspicious} suspicious detections for the direct indicator.")
                elif suspicious > 0:
                    contribution = min(70, 35 + suspicious * 5)
                    adverse_direct += 1
                    reasons.append(f"VirusTotal reports {suspicious} suspicious detections for the direct indicator.")
                elif verdict == "no_threats_detected":
                    benign_direct += 1
            elif malicious > 0:
                contribution = min(55, 30 + malicious * 2)
                reasons.append("VirusTotal has adverse related-domain evidence; it is not an exact-URL verdict.")
        elif provider == "cloudflare_url_scanner":
            if direct:
                direct_usable += 1
                if verdict == "malicious":
                    contribution = 85
                    adverse_direct += 1
                    reasons.append("Cloudflare URL Scanner marks the directly checked indicator as malicious.")
                elif verdict == "no_threats_detected":
                    benign_direct += 1
            elif verdict == "malicious":
                contribution = 50
                reasons.append("Cloudflare found a malicious related resource, not an exact match.")
        elif provider == "abuseipdb":
            maximum = int((item.get("native_metrics") or {}).get("max_abuse_confidence") or 0)
            if maximum >= 80:
                contribution = 24
                reasons.append("A resolved IP has high abuse reports; this is infrastructure context and not a URL verdict.")
            elif maximum >= 40:
                contribution = 12
                reasons.append("A resolved IP has some abuse reports; shared hosting or CDN use may limit relevance.")

        if expired:
            contribution = round(contribution * 0.6)
            if contribution:
                reasons.append(f"{provider.replace('_', ' ').title()} evidence is older than its freshness window.")
        target = direct_scores if direct else context_scores
        if contribution:
            target.append(contribution)
        contributions.append({
            "provider": provider,
            "scope": scope,
            "native_verdict": verdict,
            "sec360_contribution": contribution,
            "expired": expired,
        })

    score: int | None
    if direct_scores:
        score = max(direct_scores)
        if context_scores:
            score = min(100, score + min(10, max(context_scores) // 3))
    elif direct_usable and benign_direct:
        score = 10
    elif context_scores:
        # Infrastructure-only evidence cannot create a high URL verdict.
        score = min(24, max(context_scores))
    else:
        score = None

    if score is None:
        level = "unknown"
        reasons.insert(0, "Insufficient direct reputation evidence is available for a Sec360 risk score.")
    else:
        level = next(label for minimum, label in risk_bands if score >= minimum)
        if score < 25 and benign_direct:
            reasons.insert(0, "No threats were detected in the available evidence; this does not guarantee the indicator is safe.")

    if adverse_direct and benign_direct:
        reasons.append("Direct reputation sources disagree; review each provider's evidence.")
    coverage = {
        "usable": usable,
        "applicable": len(REPUTATION_PROVIDERS),
        "label": f"{usable} of {len(REPUTATION_PROVIDERS)} applicable reputation sources returned usable results",
    }
    confidence_points = usable + direct_usable + (1 if fresh >= max(1, usable) else 0)
    if score is None or usable <= 1 or confidence_points <= 2:
        confidence = "low"
    elif confidence_points >= 5 and not (adverse_direct and benign_direct):
        confidence = "high"
    else:
        confidence = "medium"
    return {
        "risk_score": score,
        "risk_level": level,
        "evidence_confidence": confidence,
        "coverage": coverage,
        "reasons": reasons[:6],
        "provider_contributions": contributions,
        "scoring_version": SCORING_VERSION,
    }
