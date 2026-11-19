"""Live acceptance check of Blue and all four Red Advance layers.

Run separately from offline pytest: this command uses the configured API keys.
Only the synthetic lab system prompts and a banking question are sent.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agents.agent import create_blue_agent
from agents.guards_agent import create_red_agent_advance, RedAdvanceGuardPlugin
from assignment.pipeline import build_production_plugins
from attacks.attacks import classify_attack_outcome, response_leaked_secrets
from core.config import blue_provider_label, red_provider_label
from core.utils import chat_with_agent


async def main():
    question = "Explain what a savings account is in one short sentence."
    blue, blue_runner = create_blue_agent(build_production_plugins())
    blue_text, _ = await chat_with_agent(blue, blue_runner, question)
    assert blue_text.strip() and not blue_runner.last_outcome["blocked"]
    assert blue_runner.last_outcome["llm_called"] and not response_leaked_secrets(blue_text)

    advance, runner = create_red_agent_advance()
    text, _ = await chat_with_agent(advance, runner, question)
    outcome = classify_attack_outcome(question, text, target_name="red_advance")
    assert text.strip() and not outcome["blocked"] and not outcome["leaked"]
    assert outcome["layer"] is None, "A benign banking question was refused or failed."
    plugins = runner.plugins if hasattr(runner, "plugins") else runner.plugin_manager.plugins
    guard = next(p for p in plugins if isinstance(p, RedAdvanceGuardPlugin))
    assert guard.nemo.stats["input_checked"] == 1
    assert guard.nemo.stats["output_checked"] == 1
    assert guard.nemo.stats["errors"] == 0
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "live API calls, no fake model",
        "blue": {"provider_model": blue_provider_label(), "response": blue_text,
                 "outcome": blue_runner.last_outcome},
        "red_advance": {"provider_model": red_provider_label(), "response": text,
                        "outcome": outcome, "guard_stats": guard.stats,
                        "nemo_stats": guard.nemo.stats},
        "passed": True,
    }
    out = ROOT / "outputs" / "runtime_health.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print("LIVE ACCEPTANCE PASS: Blue + Red Advance input/model/output; NeMo errors=0")


if __name__ == "__main__":
    asyncio.run(main())
