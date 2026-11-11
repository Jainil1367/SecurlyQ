"""Model output is untrusted: each guard below has a test that tries to get past it."""

import json

import pytest

from app.llm.explainer import OutputRejected, validate_output
from app.llm.record import build_incident_record
from tests.llm.helpers import attack_evidence, good_output, make_alert


@pytest.fixture()
def rec():
    return build_incident_record(make_alert(), attack_evidence())


def reject_reason(raw, rec):
    with pytest.raises(OutputRejected) as exc:
        validate_output(raw if isinstance(raw, str) else json.dumps(raw), rec)
    return str(exc.value)


def test_valid_output_is_accepted(rec):
    body = validate_output(json.dumps(good_output()), rec)
    assert "account-1" in body.summary


def test_json_wrapped_in_prose_or_fence_is_still_extracted(rec):
    raw = "Sure! Here it is:\n```json\n" + json.dumps(good_output()) + "\n```"
    # a markdown fence is stripped by extraction; the fence itself is outside the JSON object
    assert validate_output(raw, rec).uncertainty


@pytest.mark.parametrize("raw", ["", "I cannot help with that.", "[1, 2, 3]", "{not json}"])
def test_non_json_is_rejected(rec, raw):
    assert reject_reason(raw, rec) in {"no_json_object", "schema_mismatch"}


def test_missing_key_is_rejected(rec):
    body = good_output()
    del body["uncertainty"]
    assert reject_reason(body, rec) == "schema_mismatch"


def test_extra_key_is_rejected(rec):
    assert reject_reason({**good_output(), "action": "block_ip"}, rec) == "schema_mismatch"


def test_wrong_types_and_lengths_are_rejected(rec):
    assert reject_reason(good_output(why_flagged="not a list"), rec) == "schema_mismatch"
    assert reject_reason(good_output(summary="short"), rec) == "schema_mismatch"
    assert reject_reason(good_output(investigation_steps=["only one"]), rec) == "schema_mismatch"
    assert reject_reason(good_output(summary="x" * 5000), rec) == "schema_mismatch"


@pytest.mark.parametrize("url", ["Visit https://evil.example/login to verify.", "See www.evil.example now.", "ftp://x.y/z"])
def test_urls_are_rejected(rec, url):
    assert reject_reason(good_output(investigation_steps=[url, "Check account-1 activity."]), rec) == "contains_url"


@pytest.mark.parametrize("cmd", ["Run sudo iptables -A INPUT -s 203.0.113.9 -j DROP", "curl the endpoint", "```bash\nls\n```"])
def test_commands_and_code_are_rejected(rec, cmd):
    assert reject_reason(good_output(investigation_steps=[cmd, "Check account-1 activity."]), rec) == "contains_command_or_code"


def test_automated_actions_are_rejected(rec):
    steps = ["Automatically block 203.0.113.9 at the firewall.", "Review account-1 activity."]
    assert reject_reason(good_output(investigation_steps=steps), rec) == "recommends_automated_action"


@pytest.mark.parametrize("claim", ["This is definitely an attack.", "A confirmed breach occurred.", "The account was certainly compromised."])
def test_overconfident_claims_are_rejected(rec, claim):
    assert reject_reason(good_output(summary=claim + " Account-1 had many failed logins from 203.0.113.9."), rec) == "overconfident_claim"


def test_cautious_language_is_allowed(rec):
    ok = good_output(uncertainty="Whether the sign-in was malicious cannot be verified from logs alone; it is not proven.")
    assert validate_output(json.dumps(ok), rec)


def test_overclaim_guard_is_deliberately_conservative(rec):
    """It cannot read negation, so "was confirmed" is refused even in an honest sentence.
    A false rejection only costs a safe template fallback; a false accept would break the
    product rule that SecurlyQ never claims an attack is confirmed."""
    honest = good_output(uncertainty="Whether this was confirmed as malicious cannot be known from logs alone.")
    assert reject_reason(honest, rec) == "overconfident_claim"


def test_hallucinated_ip_is_rejected(rec):
    bad = good_output(why_flagged=["Traffic also came from 198.51.100.77 earlier.", "12 failed logins occurred."])
    assert reject_reason(bad, rec) == "mentions_unknown_ip"


def test_hallucinated_account_is_rejected(rec):
    bad = good_output(why_flagged=["account-7 was also targeted.", "12 failed logins occurred."])
    assert reject_reason(bad, rec) == "mentions_unknown_account"
