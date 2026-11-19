"""
Lab 11 — Configuration, provider selection, API keys.

Hai tầng model (không trộn):

  Blue Team (CP2–CP3, guardrails / pipeline / protected agent)
    → OpenRouter ``liquid/lfm-3-1.7b:free`` (mặc định)
    → Hoặc Liquid trực tiếp ``lfm3-1.7b`` với ``BLUE_PROVIDER=liquid``
    → Key tương ứng: ``OPENROUTER_API_KEY`` / ``LIQUID_API_KEY``

  Red Team (CP4)
    → Chọn provider: OpenAI, Gemini hoặc CKey (OpenAI-compatible)
    → Model mềm (điểm bắt buộc CP4): ``gpt-4o-mini`` / ``gemini-3.5-flash``
    → Model khó (tuỳ chọn): ``gpt-5.6-luna`` / ``gemini-3.8-flash``
    → Bonus: chọn một — leak **Red** tối đa +5 **hoặc** leak **Red Advance** tối đa +10
    → ``RED_TEAM_PROVIDER=openai|gemini|ckey`` (alias: ``LLM_PROVIDER``)
"""
from __future__ import annotations

import os
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]

try:
    from dotenv import load_dotenv

    load_dotenv(_ROOT / ".env")
except ImportError:
    pass

# --- Providers ---
PROVIDER_OPENAI = "openai"
PROVIDER_GEMINI = "gemini"
PROVIDER_OPENROUTER = "openrouter"
PROVIDER_LIQUID = "liquid"
PROVIDER_CKEY = "ckey"

# --- Blue Team (LOCKED) ---
BLUE_PROVIDER = PROVIDER_OPENROUTER
BLUE_MODEL = "liquid/lfm-3-1.7b:free"
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_OPENROUTER_MODEL = BLUE_MODEL  # alias
LIQUID_BLUE_MODEL = "lfm3-1.7b"
LIQUID_BASE_URL = "https://api.liquid.ai/openai/v1"

# --- Red Team ---
DEFAULT_OPENAI_MODEL = "gpt-4o-mini"
DEFAULT_GEMINI_MODEL = "gemini-3.5-flash"
DEFAULT_CKEY_MODEL = "claude-opus-5"
CKEY_BASE_URL = "https://api.xah.io/v1"
# Model khó — tuỳ chọn (không phải tên agent; không bắt buộc để có B1/B2)
HARD_OPENAI_MODEL = "gpt-5.6-luna"
HARD_GEMINI_MODEL = "gemini-3.8-flash"

# --- Protected data (DEMO) ---
PROTECTED_DATA_DIR = _ROOT / "data" / "protected"
PROTECTED_SECRETS_PATH = PROTECTED_DATA_DIR / "vinbank_secrets.json"


def load_protected_payload() -> dict:
    """Load DEMO secrets JSON used by agents + leak detection."""
    import json

    if not PROTECTED_SECRETS_PATH.is_file():
        raise FileNotFoundError(
            f"Missing protected data file: {PROTECTED_SECRETS_PATH}. "
            "Expected data/protected/vinbank_secrets.json in the starter repo."
        )
    return json.loads(PROTECTED_SECRETS_PATH.read_text(encoding="utf-8"))


def _build_demo_secrets() -> tuple[list[str], str]:
    data = load_protected_payload()
    secrets_map = data.get("secrets") or {}
    needles: list[str] = []
    for target in data.get("leak_targets") or []:
        for s in target.get("match_substrings") or []:
            if s and s not in needles:
                needles.append(s)
        val = (target.get("value") or "").strip()
        if val and ":" in val:
            host = val.split(":", 1)[0]
            if host and host not in needles:
                needles.append(host)
    if not needles:
        needles = [str(v) for v in secrets_map.values() if v]

    note = (
        f"admin password {secrets_map.get('admin_password', '')}; "
        f"API key {secrets_map.get('api_key', '')}; "
        f"DB at {secrets_map.get('db_host', '')}"
    )
    return needles, note


try:
    DEMO_SECRETS, DEMO_SECRET_NOTE = _build_demo_secrets()
except FileNotFoundError:
    DEMO_SECRETS = []
    DEMO_SECRET_NOTE = "protected data missing — see data/protected/vinbank_secrets.json"


# ---------------------------------------------------------------------------
# Blue Team — fixed LFM3-1.7B via OpenRouter or Liquid directly
# ---------------------------------------------------------------------------

def get_blue_provider() -> str:
    provider = os.environ.get("BLUE_PROVIDER", BLUE_PROVIDER).strip().lower() or BLUE_PROVIDER
    if provider not in {PROVIDER_OPENROUTER, PROVIDER_LIQUID}:
        raise ValueError("BLUE_PROVIDER phải là openrouter hoặc liquid.")
    return provider


def get_blue_model() -> str:
    # Same model family; provider-specific API identifiers are fixed.
    return LIQUID_BLUE_MODEL if get_blue_provider() == PROVIDER_LIQUID else BLUE_MODEL


def get_openrouter_api_key() -> str:
    return os.environ.get("OPENROUTER_API_KEY", "").strip()


def get_blue_api_key() -> str:
    if get_blue_provider() == PROVIDER_LIQUID:
        return os.environ.get("LIQUID_API_KEY", "").strip()
    return get_openrouter_api_key()


def blue_client_kwargs() -> dict:
    """OpenAI-compatible client for the selected Blue provider."""
    if get_blue_provider() == PROVIDER_LIQUID:
        return {"api_key": get_blue_api_key() or None, "base_url": LIQUID_BASE_URL}
    return {
        "api_key": get_blue_api_key() or None,
        "base_url": (
            os.environ.get("OPENROUTER_BASE_URL", OPENROUTER_BASE_URL).strip()
            or OPENROUTER_BASE_URL
        ),
    }


def blue_provider_label() -> str:
    return f"{get_blue_provider()}:{get_blue_model()}"


# ---------------------------------------------------------------------------
# Red Team — openai | gemini | ckey
# ---------------------------------------------------------------------------

def get_red_provider() -> str:
    raw = (
        os.environ.get("RED_TEAM_PROVIDER")
        or os.environ.get("LLM_PROVIDER")
        or "openai"
    ).strip().lower()
    if raw in {"gemini", "google", "adk"}:
        return PROVIDER_GEMINI
    if raw == PROVIDER_CKEY:
        return PROVIDER_CKEY
    return PROVIDER_OPENAI


def get_red_model() -> str:
    """Model Red Team từ .env (cùng cho default + advance)."""
    if get_red_provider() == PROVIDER_GEMINI:
        return (
            os.environ.get("GEMINI_MODEL", DEFAULT_GEMINI_MODEL).strip()
            or DEFAULT_GEMINI_MODEL
        )
    default = DEFAULT_CKEY_MODEL if get_red_provider() == PROVIDER_CKEY else DEFAULT_OPENAI_MODEL
    return os.environ.get("OPENAI_MODEL", default).strip() or default


def get_red_model_default() -> str:
    """Alias — Red dùng cùng model .env."""
    return get_red_model()


def get_red_model_advance() -> str:
    """Alias — Red Advance dùng cùng model .env."""
    return get_red_model()


def get_openai_api_key() -> str:
    return os.environ.get("OPENAI_API_KEY", "").strip()


def get_red_base_url(provider: str | None = None) -> str:
    """Shared endpoint for Red's runner and NeMo self-checks."""
    provider = provider or get_red_provider()
    default = CKEY_BASE_URL if provider == PROVIDER_CKEY else "https://api.openai.com/v1"
    return os.environ.get("OPENAI_BASE_URL", default).strip() or default


def red_openai_client_kwargs() -> dict:
    return {
        "api_key": get_openai_api_key() or None,
        "base_url": get_red_base_url(),
    }


def red_provider_label(tier: str = "advance") -> str:
    # tier giữ để tương thích call site; cả hai agent cùng model .env
    _ = tier
    return f"{get_red_provider()}:{get_red_model()}"


def red_uses_openai_sdk() -> bool:
    return get_red_provider() in {PROVIDER_OPENAI, PROVIDER_CKEY}


def red_uses_gemini() -> bool:
    return get_red_provider() == PROVIDER_GEMINI


# ---------------------------------------------------------------------------
# Backward-compatible aliases (mean RED TEAM — used by attack JSON / grade)
# ---------------------------------------------------------------------------

def get_llm_provider() -> str:
    return get_red_provider()


def get_model_name() -> str:
    """Model khai trong attack_results — khớp .env lúc chạy CP4."""
    return get_red_model()


def uses_openai_sdk() -> bool:
    """True for OpenAI-compatible Red providers (OpenAI or CKey)."""
    return red_uses_openai_sdk()


def openai_compatible_client_kwargs() -> dict:
    """Default client kwargs = Red Team OpenAI (not Blue/OpenRouter)."""
    return red_openai_client_kwargs()


def provider_label() -> str:
    return red_provider_label()


def is_harder_model() -> bool:
    """True nếu .env đang trỏ model khó (luna / 3.8) — tuỳ chọn, không phải tên agent."""
    m = get_red_model().lower()
    if m in {DEFAULT_OPENAI_MODEL.lower(), DEFAULT_GEMINI_MODEL.lower()}:
        return False
    hard = {
        HARD_OPENAI_MODEL.lower(),
        HARD_GEMINI_MODEL.lower(),
        "gpt-5.6-sol",
        "gpt-5.6-terra",
        "gpt-4o",
        "gemini-3.7-flash",
        "gemini-3.6-flash",
        "gemini-2.5-pro",
    }
    if m in hard:
        return True
    return any(x in m for x in ("gpt-5.6", "pro", "gemini-3.8", "gemini-3.7"))


def setup_api_key():
    """Ensure keys for Blue + Red / Red Advance (OpenAI or Gemini)."""
    if not get_blue_api_key():
        direct = get_blue_provider() == PROVIDER_LIQUID
        key_name = "LIQUID_API_KEY" if direct else "OPENROUTER_API_KEY"
        label = "Liquid" if direct else "OpenRouter"
        os.environ[key_name] = input(f"Enter {label} API Key (Blue): ").strip()
    print(f"Blue  — {blue_provider_label()}  [LOCKED]")

    red = get_red_provider()
    model = get_red_model()
    if red == PROVIDER_GEMINI:
        if not os.environ.get("GOOGLE_API_KEY", "").strip():
            os.environ["GOOGLE_API_KEY"] = input("Enter Google API Key (Red): ").strip()
        os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "0"
        print(f"Red / Red Advance  — gemini:{model}")
    else:
        if not get_openai_api_key():
            label = "CKey" if red == PROVIDER_CKEY else "OpenAI"
            os.environ["OPENAI_API_KEY"] = input(f"Enter {label} API Key (Red): ").strip()
        print(f"Red / Red Advance  — {red}:{model}")

    print(
        "Bonus: chọn một — Red tối đa +5 (B1) hoặc Red Advance tối đa +10 (B2)."
    )
    if is_harder_model():
        print(
            f"Model khó ({model}) — tuỳ chọn; không đổi tên agent. "
            f"(Gợi ý: {HARD_OPENAI_MODEL} / {HARD_GEMINI_MODEL})"
        )


ALLOWED_TOPICS = [
    "banking", "account", "transaction", "transfer",
    "loan", "interest", "savings", "credit",
    "deposit", "withdrawal", "balance", "payment",
    "tai khoan", "giao dich", "tiet kiem", "lai suat",
    "chuyen tien", "the tin dung", "so du", "vay",
    "ngan hang", "atm",
]

BLOCKED_TOPICS = [
    "hack", "exploit", "weapon", "drug", "illegal",
    "violence", "gambling", "bomb", "kill", "steal",
]
