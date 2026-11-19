"""Regression checks for evasion, false positives, and no pre-LLM execution."""
import asyncio
import base64
import codecs
from urllib.parse import quote

import pytest

from agents.agent import create_blue_agent
from assignment.pipeline import build_production_plugins, is_egress_allowed
from guardrails.input_guardrails import detect_injection, topic_filter
from guardrails.output_guardrails import content_filter
from guardrails.security_text import inspection_views, MAX_VIEWS
from testing.scenarios import attack_defense_scenarios


@pytest.mark.parametrize("case", attack_defense_scenarios(), ids=lambda c: c["category"])
def test_scenario_input_decision(case):
    blocked = detect_injection(case["input"]) == "BLOCK" or topic_filter(case["input"]) == "BLOCK"
    assert blocked == case["expected_blocked"]


def test_rejected_encoded_text_never_reaches_provider(monkeypatch):
    agent, runner = create_blue_agent(build_production_plugins())
    def forbidden_client():
        raise AssertionError("provider must not be called for rejected input")
    monkeypatch.setattr(runner, "_client", forbidden_client)
    case = next(c for c in attack_defense_scenarios() if c["category"] == "nested_base64")
    reply = asyncio.run(runner.chat(agent, case["input"]))
    assert reply and runner.last_outcome["blocked"] and not runner.last_outcome["llm_called"]


@pytest.mark.parametrize("encoder", [lambda s: base64.b64encode(s.encode()).decode(),
                                     lambda s: s.encode().hex(), lambda s: quote(s, safe=""),
                                     lambda s: codecs.encode(s, "rot_13"), lambda s: s[::-1],
                                     lambda s: "".join(f"&#{ord(c)};" for c in s)])
def test_encoded_secret_withheld_from_reply_and_egress(encoder):
    from core.config import DEMO_SECRETS
    payload = encoder(DEMO_SECRETS[0])
    result = content_filter(payload)
    assert not result["safe"] and payload not in result["redacted"]
    assert not is_egress_allowed("https://api.vinbank.example/v1/cases", payload)


def test_decoder_is_bounded_and_does_not_execute_or_corrupt_input():
    malformed = "banking !!!%%%\\uZZZZ <script>alert(1)</script>"
    views = inspection_views(malformed)
    assert views[0] == malformed and len(views) <= MAX_VIEWS
    large = "x" * 12001
    assert inspection_views(large) == [large]
    assert detect_injection(large) == "BLOCK"
    assert all(isinstance(v, str) and len(v) <= 12000 for v in inspection_views("banking " * 1000))
