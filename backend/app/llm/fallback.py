"""Deterministic explanation built from templates and the sanitized record.

Reliability lesson: a feature that depends on a third-party service needs a floor. If
Bedrock is disabled, throttled, down, or returns something we reject, analysts still get a
useful, honest explanation. It is also the baseline that shows what the LLM adds.
"""

from datetime import UTC, datetime

from app.llm.record import IncidentRecord
from app.schemas.explanation import ExplanationOut

_BENIGN = {
    "failed_login_burst": [
        "A user or script with a stale saved password retrying repeatedly.",
        "A shared office or VPN address where several people mistyped passwords at once.",
        "An internal security scan or penetration test.",
    ],
    "failure_then_success": [
        "A legitimate user who mistyped their password several times before getting it right.",
        "A password manager or script that retried with an outdated credential first.",
    ],
    "multi_ip_login": [
        "The person switched between home, mobile, and VPN connections.",
        "A shared account used by several teammates.",
    ],
    "anomaly_isolation_forest": [
        "A legitimate but unusual event such as a new office, a migration, or a load test.",
        "A new automated integration that logs in on a schedule.",
    ],
}

_STEPS = {
    "failed_login_burst": [
        "Check whether the targeted account(s) exist and whether any of the attempts succeeded.",
        "Look up the source IP in your allow-lists and in other events from the last 24 hours.",
        "Confirm that the account owner has recently had password problems.",
    ],
    "failure_then_success": [
        "Contact the account owner and ask whether they logged in at that time.",
        "Review what the account did after the successful login.",
        "Check for other logins from the same IP and for password-reset activity.",
    ],
    "multi_ip_login": [
        "Ask the account owner whether they were travelling or using a VPN.",
        "Compare the locations and networks of the listed IP addresses.",
        "Review activity on the account between the first and last login.",
    ],
    "anomaly_isolation_forest": [
        "Review the listed events and compare them with this IP's usual behaviour.",
        "Check whether the source IP belongs to a known partner, scanner, or office.",
        "Look for related activity from the same IP before and after this window.",
    ],
}
_DEFAULT_BENIGN = ["Legitimate but unusual user or system behaviour."]
_DEFAULT_STEPS = [
    "Review the evidence events listed with this alert.",
    "Check whether the source and account are known and expected.",
    "Look for related activity before and after these events.",
]


def build_fallback(record: IncidentRecord, reason: str) -> ExplanationOut:
    d = record.data
    alert, s = d["alert"], d["summary_of_all_evidence"]
    rule = alert["rule"]
    where = f" from {alert['source_ip']}" if alert["source_ip"] else ""
    minutes = max(1, round(s["duration_seconds"] / 60))

    summary = (
        f"SecurlyQ flagged potentially suspicious login activity{where}: {alert['rule_description']} "
        f"The evidence contains {s['total_events']} events over about {minutes} minute(s), "
        f"with {s['failed_logins']} failed and {s['successful_logins']} successful logins."
    )
    why = [
        f"Severity {alert['severity']} with risk score {alert['risk_score_0_to_100']} out of 100.",
        (
            f"{s['failed_logins']} failed and {s['successful_logins']} successful logins across "
            f"{s['distinct_accounts']} account(s) and {s['distinct_ips']} IP address(es)."
        ),
    ]
    if alert["anomaly_percentile_0_to_1"] is not None:
        why.append(
            f"The anomaly model rates this activity as more unusual than "
            f"{alert['anomaly_percentile_0_to_1']:.0%} of normal traffic."
        )
    return ExplanationOut(
        summary=summary,
        why_flagged=why,
        benign_possibilities=_BENIGN.get(rule, _DEFAULT_BENIGN),
        investigation_steps=_STEPS.get(rule, _DEFAULT_STEPS),
        uncertainty=(
            "This summary is generated from counts and timing only. It cannot tell whether the person "
            "behind the activity was authorized, so it is not evidence of an attack by itself."
        ),
        source="fallback",
        model_id=None,
        generated_at=datetime.now(UTC),
        fallback_reason=reason,
    )
