"""
ai_providers.py — Multi-provider AI integration for GitHub AI Repo Bot

Supported providers:
  groq       — Groq API       (live account model discovery)                  FREE tier
  gemini     — Google Gemini  (Gemini 3.8 Flash and current Gemini models)   FREE tier
  mistral    — Mistral AI     (Mistral Medium 3.5 and current aliases)       FREE tier
  together   — Together AI    (hosted open and commercial models)            PAID
  openai     — OpenAI         (GPT-6 model family)                            PAID
  openrouter — OpenRouter     (multi-provider model gateway)                 PAID/FREE
  anthropic  — Anthropic      (Claude 5 model family)                         PAID
  xai        — xAI            (Grok 4.7 and current Grok models)             PAID
  deepseek   — DeepSeek       (DeepSeek V4 Pro and V4.1 Flash)               PAID
"""

from __future__ import annotations

import re
from typing import Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import config as _config
    _MAX_RETRIES = _config.HTTP_MAX_RETRIES
except Exception:  # pragma: no cover
    _MAX_RETRIES = 3

_retry = Retry(
    total=_MAX_RETRIES,
    backoff_factor=0.5,
    status_forcelist=(429, 500, 502, 503, 504),
    allowed_methods=("GET", "POST"),
    raise_on_status=False,
)
_session = requests.Session()
_adapter = HTTPAdapter(max_retries=_retry, pool_connections=10, pool_maxsize=10)
_session.mount("https://", _adapter)
_session.mount("http://", _adapter)


def groq_available_models(api_key: str, timeout: int = 15) -> set[str]:
    """Return model IDs visible to this Groq key.

    Groq can change model availability independently of this bot release, and
    model access can also vary by account.  The Models endpoint is therefore a
    better source of truth than a static list in the application.
    """
    try:
        r = _session.get(
            "https://api.groq.com/openai/v1/models",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=timeout,
        )
    except requests.exceptions.ConnectionError:
        raise AIError("network_error", "🌐 Could not reach Groq while checking available models.")
    except requests.exceptions.Timeout:
        raise AIError("timeout", "⏱ Groq's model list request timed out. Try again.")
    except requests.exceptions.RequestException as e:
        raise AIError("request_error", f"❌ Groq model lookup failed: `{e}`")
    if r.status_code != 200:
        try:
            err_body = r.json()
        except Exception:
            err_body = {}
        raise _diagnose_http(r.status_code, err_body, "groq")
    try:
        return {
            item["id"] for item in r.json().get("data", [])
            if isinstance(item, dict) and item.get("id")
        }
    except (AttributeError, TypeError, KeyError):
        raise AIError("parse_error", "❌ Couldn't parse Groq's model list.")


def resolve_groq_model(api_key: str, requested: str | None = None) -> str:
    """Choose a model that is both current and visible to the supplied key."""
    available = groq_available_models(api_key)
    preferred = [
        requested,
        PROVIDERS["groq"]["default"],
        "openai/gpt-oss-20b",
        "llama-3.1-8b-instant",
    ]
    for model in preferred:
        if model and model in available:
            return model
    raise AIError(
        "model_not_found",
        "❌ No supported text model is available for this Groq API key.\n\n"
        "Check the key's model permissions in GroqCloud or choose another provider.",
    )

# ── Provider registry ──────────────────────────────────────────

PROVIDERS: dict[str, dict] = {
    "groq": {
        "name":    "Groq",
        "emoji":   "⚡",
        "free":    True,
        "url":     "https://api.groq.com/openai/v1/chat/completions",
        "style":   "openai_compat",
        "models": [
            "openai/gpt-oss-120b",         # strongest open-weight production model
            "openai/gpt-oss-20b",          # fastest open-weight production model
            "llama-3.3-70b-versatile",     # reliable general-purpose model
            "llama-3.1-8b-instant",        # fastest Llama model
            "groq/compound",               # web search + code execution system
            "groq/compound-mini",          # faster Compound system
        ],
        "default": "openai/gpt-oss-120b",
        "get_key": "console.groq.com/keys",
        "max_tokens_param": "max_completion_tokens",
    },
    "gemini": {
        "name":    "Google Gemini",
        "emoji":   "✨",
        "free":    True,
        "url":     "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        "style":   "gemini",
        "models": [
            "gemini-3.8-flash",            # latest stable Flash
            "gemini-3.7-flash",            # previous stable Flash
            "gemini-3.6-flash",            # previous stable Flash
            "gemini-3.5-flash",            # stable legacy Flash
            "gemini-3.5-flash-lite",       # fastest stable option
            "gemini-3.1-flash-lite",       # low-cost high-throughput option
            "gemini-3.1-pro-preview",      # strongest reasoning preview
        ],
        "default": "gemini-3.8-flash",
        "get_key": "aistudio.google.com/apikey",
    },
    "together": {
        "name":    "Together AI",
        "emoji":   "🤝",
        "free":    False,
        "url":     "https://api.together.xyz/v1/chat/completions",
        "style":   "openai_compat",
        "models": [
            "openai/gpt-oss-120b",
            "Qwen/Qwen3.5-397B-A17B",
            "moonshotai/Kimi-K2.5",
            "deepseek-ai/DeepSeek-V3.1",
            "MiniMaxAI/MiniMax-M2.5",
            "Qwen/Qwen3.5-9B",
        ],
        "default": "openai/gpt-oss-120b",
        "get_key": "api.together.ai",
    },
    "mistral": {
        "name":    "Mistral AI",
        "emoji":   "🌀",
        "free":    True,
        "url":     "https://api.mistral.ai/v1/chat/completions",
        "style":   "openai_compat",
        "models": [
            "mistral-medium-3-5",          # current frontier-class model
            "mistral-large-latest",
            "mistral-medium-latest",
            "mistral-small-latest",
            "ministral-3-14b-25-12",       # compact multimodal model
            "ministral-3-8b-25-12",        # fast compact model
            "ministral-3-3b-25-12",        # lowest-latency compact model
        ],
        "default": "mistral-medium-3-5",
        "get_key": "console.mistral.ai/api-keys",
    },
    "openai": {
        "name":    "OpenAI",
        "emoji":   "🧠",
        "free":    False,
        "url":     "https://api.openai.com/v1/chat/completions",
        "style":   "openai_compat",
        "models": [
            "gpt-6-luna",                  # efficient, low-cost current model
            "gpt-6.1-sol",                 # balanced quality and cost
            "gpt-6-astra",                 # highest capability
            "gpt-5.6-terra",               # previous generation balanced option
        ],
        "default": "gpt-6-luna",
        "get_key": "platform.openai.com/api-keys",
        "max_tokens_param": "max_completion_tokens",
    },
    "openrouter": {
        "name":    "OpenRouter",
        "emoji":   "🔀",
        "free":    False,
        "url":     "https://openrouter.ai/api/v1/chat/completions",
        "style":   "openai_compat",
        "models": [
            "~openai/gpt-latest",          # OpenRouter maintained latest alias
            "openai/gpt-6-luna",
            "anthropic/claude-sonnet-5-5",
            "google/gemini-3.8-flash",
            "deepseek/deepseek-flash",
        ],
        "default": "~openai/gpt-latest",
        "get_key": "openrouter.ai/keys",
    },
    "anthropic": {
        "name":    "Anthropic Claude",
        "emoji":   "🧠",
        "free":    False,
        "url":     "https://api.anthropic.com/v1/messages",
        "style":   "anthropic",
        "models": [
            "claude-sonnet-5-5",
            "claude-opus-5",
            "claude-sonnet-5",
            "claude-opus-4-8",
            "claude-haiku-4-5-20251001",
        ],
        "default": "claude-sonnet-5-5",
        "get_key": "console.anthropic.com/settings/keys",
    },
    "xai": {
        "name":    "xAI Grok",
        "emoji":   "🛰️",
        "free":    False,
        "url":     "https://api.x.ai/v1/chat/completions",
        "style":   "openai_compat",
        "models": ["grok-4.7", "grok-4.6", "grok-4.20-0309-reasoning"],
        "default": "grok-4.7",
        "get_key": "console.x.ai",
        "max_tokens_param": "max_tokens",
    },
    "deepseek": {
        "name":    "DeepSeek",
        "emoji":   "🔎",
        "free":    False,
        "url":     "https://api.deepseek.com/chat/completions",
        "style":   "openai_compat",
        "models": ["deepseek-v4-pro", "deepseek-flash", "deepseek-v4-flash"],
        "default": "deepseek-flash",
        "get_key": "platform.deepseek.com/api_keys",
        "max_tokens_param": "max_tokens",
    },
}

FREE_PROVIDERS = [k for k, v in PROVIDERS.items() if v["free"]]


# ── Error types ────────────────────────────────────────────────

class AIError(Exception):
    """Structured AI error with user-facing message."""
    def __init__(self, code: str, message: str, detail: str = ""):
        self.code    = code
        self.message = message
        self.detail  = detail
        super().__init__(message)


def _diagnose_http(status: int, body: dict, provider: str) -> AIError:
    """Turn an HTTP error into a clear, actionable AIError."""
    if not isinstance(body, dict):
        body = {}
    raw = body.get("error", {})
    if not isinstance(raw, dict):
        raw = {"message": str(raw)}
    raw_msg = (raw.get("message") or body.get("message") or str(body))[:200]

    if status == 401:
        return AIError(
            "auth_failed",
            f"❌ *{provider} API key is invalid or expired.*\n\n"
            f"Double-check your key at: `{PROVIDERS[provider]['get_key']}`\n"
            f"Then re-run: `/setai {provider} YOUR_KEY {PROVIDERS[provider]['default']}`",
            raw_msg,
        )
    if status == 403:
        return AIError(
            "forbidden",
            f"❌ *{provider} returned 403 Forbidden.*\n\n"
            f"Your key may lack permissions or the model may be restricted.",
            raw_msg,
        )
    if status == 404:
        p = PROVIDERS[provider]
        models_list = "\n".join(f"  • `{m}`" for m in p["models"][:5])
        return AIError(
            "model_not_found",
            f"❌ *Model not found on {provider}.*\n\n"
            f"Available models:\n{models_list}\n\n"
            f"Fix: `/setai {provider} YOUR_KEY {p['default']}`",
            raw_msg,
        )
    if status == 429:
        return AIError(
            "rate_limited",
            f"⏳ *{provider} rate limit hit.*\n\n"
            f"Wait a moment and try again, or switch providers with `/models`.",
            raw_msg,
        )
    if status in (500, 502, 503):
        return AIError(
            "server_error",
            f"⚠️ *{provider} server error (HTTP {status}).*\n\n"
            f"This is their side. Try again in 30 seconds.",
            raw_msg,
        )
    return AIError(
        "http_error",
        f"❌ *{provider} returned HTTP {status}.*\n\n`{raw_msg}`",
        raw_msg,
    )


# ── Core generate ──────────────────────────────────────────────

def generate(
    provider: str,
    api_key:  str,
    model:    str,
    prompt:   str,
    max_tokens: int = 1500,
    timeout:  int  = 30,
    temperature: float = 0.7,
) -> str:
    """
    Call AI and return the response text.
    Raises AIError on any failure (never returns None).

    temperature: lower = more focused/deterministic, higher = more varied/creative.
    Use ~0.2-0.3 for structured/extraction tasks (names, descriptions, JSON specs)
    and ~0.6-0.8 for free-form creative writing (README prose).
    """
    if provider not in PROVIDERS:
        known = ", ".join(PROVIDERS.keys())
        raise AIError(
            "unknown_provider",
            f"❌ Unknown provider `{provider}`.\n\nAvailable: `{known}`",
        )

    info = PROVIDERS[provider]

    try:
        if info["style"] == "openai_compat":
            return _call_openai_compat(provider, api_key, model, prompt, max_tokens, timeout, temperature)
        elif info["style"] == "gemini":
            return _call_gemini(api_key, model, prompt, timeout, temperature)
        elif info["style"] == "anthropic":
            return _call_anthropic(api_key, model, prompt, max_tokens, timeout, temperature)
        else:
            raise AIError("config_error", f"Unknown style for provider {provider}")

    except AIError:
        raise
    except requests.exceptions.ConnectionError:
        raise AIError(
            "network_error",
            f"🌐 *Could not reach {provider}.*\n\nCheck your internet connection.",
        )
    except requests.exceptions.Timeout:
        raise AIError(
            "timeout",
            f"⏱ *{provider} request timed out after {timeout}s.*\n\nTry a faster model.",
        )
    except requests.exceptions.RequestException as e:
        raise AIError("request_error", f"❌ Network error: `{e}`")


def _call_openai_compat(
    provider: str,
    api_key:  str,
    model:    str,
    prompt:   str,
    max_tokens: int,
    timeout: int,
    temperature: float = 0.7,
) -> str:
    url = PROVIDERS[provider]["url"]
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type":  "application/json",
    }
    token_param = PROVIDERS[provider].get("max_tokens_param", "max_tokens")
    body = {
        "model":      model,
        "messages":   [{"role": "user", "content": prompt}],
        "temperature": temperature,
        "top_p": 0.9,
    }
    body[token_param] = max_tokens
    # GPT-OSS models spend part of the completion budget on reasoning. A
    # tiny setup probe such as max_tokens=10 can therefore end with no final
    # content at all. Give reasoning models enough room and request concise
    # reasoning for predictable latency.
    if model.startswith("openai/gpt-oss-"):
        body["max_completion_tokens"] = max(max_tokens, 256)
        body.pop("max_tokens", None)
        body["reasoning_effort"] = "low"
    r = _session.post(url, headers=headers, json=body, timeout=timeout)

    if r.status_code != 200:
        try:
            err_body = r.json()
        except Exception:
            err_body = {}
        raise _diagnose_http(r.status_code, err_body, provider)

    try:
        message = r.json()["choices"][0].get("message") or {}
        # Reasoning-capable models can return structured content or put the
        # usable text in reasoning_content instead of content.
        content = message.get("content") or message.get("reasoning_content") or message.get("text")
        if isinstance(content, list):
            content = "\n".join(
                part.get("text", "") if isinstance(part, dict) else str(part)
                for part in content
            )
        # Some compatible endpoints return an empty message when a tool call
        # was started. Surface that as a useful error instead of silently
        # treating the response as successful.
        if not content or not str(content).strip():
            finish_reason = r.json().get("choices", [{}])[0].get("finish_reason", "unknown")
            raise AIError(
                "empty_response",
                f"⚠️ {provider} returned an empty response (finish reason: `{finish_reason}`).",
            )
        return str(content).strip()
    except (KeyError, IndexError, AttributeError, TypeError) as e:
        raise AIError("parse_error", f"❌ Couldn't parse {provider} response: `{e}`")


def _call_gemini(api_key: str, model: str, prompt: str, timeout: int, temperature: float = 0.7) -> str:
    from urllib.parse import quote
    url = PROVIDERS["gemini"]["url"].format(model=quote(model, safe=""))
    params = {"key": api_key}
    body: dict = {"contents": [{"parts": [{"text": prompt}]}]}

    # Gemini 3.x deprecates temperature/top_p/top_k (ignored, or a hard error in
    # future releases) — only send classic sampling params to 1.x/2.x models.
    is_gemini_3 = model.startswith("gemini-3")
    if is_gemini_3:
        # Use the new thinking_level knob instead: lower level ≈ more focused output.
        thinking_level = "low" if temperature <= 0.4 else "medium"
        body["generationConfig"] = {"thinkingConfig": {"thinkingLevel": thinking_level}}
    else:
        body["generationConfig"] = {"temperature": temperature, "topP": 0.9}

    r = _session.post(url, params=params, json=body, timeout=timeout)

    if r.status_code != 200:
        try:
            err_body = r.json()
        except Exception:
            err_body = {}
        raise _diagnose_http(r.status_code, err_body, "gemini")

    try:
        candidates = r.json().get("candidates", [])
        if not candidates:
            raise AIError("empty_response", "⚠️ Gemini returned no candidates.")

        # Handle safety blocks
        finish = candidates[0].get("finishReason", "")
        if finish == "SAFETY":
            raise AIError("safety_block", "🛡 Gemini blocked the response (safety filter).")

        try:
            content = candidates[0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError, TypeError):
            raise AIError("parse_error", "❌ Couldn't parse Gemini response: missing content parts.")
        if not content.strip():
            raise AIError("empty_response", "⚠️ Gemini returned empty text.")
        return content.strip()
    except AIError:
        raise
    except (KeyError, IndexError, AttributeError, TypeError) as e:
        raise AIError("parse_error", f"❌ Couldn't parse Gemini response: `{e}`")


def _call_anthropic(
    api_key: str,
    model: str,
    prompt: str,
    max_tokens: int,
    timeout: int,
    temperature: float = 0.7,
) -> str:
    """Call Anthropic's native Messages API."""
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    body = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    # Claude's newer model families reject non-default sampling parameters;
    # omission is compatible with both old and current Claude API models.

    r = _session.post(PROVIDERS["anthropic"]["url"], headers=headers, json=body, timeout=timeout)
    if r.status_code != 200:
        try:
            err_body = r.json()
        except Exception:
            err_body = {}
        raise _diagnose_http(r.status_code, err_body, "anthropic")

    try:
        blocks = r.json().get("content", [])
        content = "\n".join(
            block.get("text", "") for block in blocks
            if isinstance(block, dict) and block.get("type") == "text"
        ).strip()
        if not content:
            raise AIError("empty_response", "⚠️ Anthropic returned an empty response.")
        return content
    except AIError:
        raise
    except (KeyError, TypeError, AttributeError) as e:
        raise AIError("parse_error", f"❌ Couldn't parse Anthropic response: `{e}`")


# ── Safe wrapper (returns None instead of raising) ─────────────

def generate_safe(
    provider: str,
    api_key:  str,
    model:    str,
    prompt:   str,
    max_tokens: int = 1500,
    temperature: float = 0.7,
) -> tuple[Optional[str], Optional[str]]:
    """Returns (text, error_message). error_message is None on success."""
    try:
        return generate(provider, api_key, model, prompt, max_tokens, temperature=temperature), None
    except AIError as e:
        # A model can disappear between deployments. Retry once with the
        # provider's current default so existing users recover automatically.
        default_model = PROVIDERS.get(provider, {}).get("default")
        if e.code == "model_not_found" and provider == "groq":
            try:
                live_model = resolve_groq_model(api_key, None)
                if live_model != model:
                    return generate(provider, api_key, live_model, prompt, max_tokens, temperature=temperature), None
            except AIError as fallback_error:
                return None, fallback_error.message
        if e.code == "model_not_found" and default_model and model != default_model:
            try:
                return generate(provider, api_key, default_model, prompt, max_tokens, temperature=temperature), None
            except AIError as fallback_error:
                return None, fallback_error.message
        return None, e.message


# ── Content helpers ────────────────────────────────────────────

def generate_readme(provider: str, api_key: str, model: str, name: str, desc: str) -> str:
    prompt = (
        f'Create a professional README.md for a GitHub project called "{name}".\n'
        f'Description: {desc or "No description provided."}\n\n'
        "Include:\n"
        "- Title with relevant emoji\n"
        "- Short description paragraph\n"
        "- ✨ Features section (4-6 bullets)\n"
        "- 📦 Installation section\n"
        "- 🚀 Usage section with code example\n"
        "- 🤝 Contributing section\n"
        "- 📄 License (MIT)\n\n"
        "Output ONLY clean Markdown. No preamble."
    )
    text, err = generate_safe(provider, api_key, model, prompt, max_tokens=1500)
    return text or f"# {name}\n\n{desc}\n\n## License\nMIT"


def generate_readme_rewrite(
    provider: str, api_key: str, model: str,
    name: str, desc: str, existing_content: str,
) -> str:
    """Rewrite an existing README.md in best GitHub format using the uploaded content as context."""
    prompt = (
        f'Project name: "{name}"\n'
        f'Description: {desc or "No description provided."}\n'
        f'Existing README content:\n---\n{existing_content[:3000]}\n---\n\n'
        "Rewrite and improve this README.md in professional GitHub format.\n"
        "Keep all real information from the original (features, usage, install steps, etc.).\n"
        "Improve structure, formatting, and clarity. Add missing standard sections.\n"
        "Use emojis for section headers. Format code blocks properly.\n"
        "Include:\n"
        "- # Title with emoji\n"
        "- Short description paragraph\n"
        "- ✨ Features (keep original points, improve wording)\n"
        "- 📦 Installation with code block\n"
        "- 🚀 Usage with examples\n"
        "- 🤝 Contributing\n"
        "- 📄 License\n\n"
        "Output ONLY clean Markdown. No preamble or explanation."
    )
    text, err = generate_safe(provider, api_key, model, prompt, max_tokens=2000)
    return text or existing_content  # fall back to original if AI fails


def generate_gitignore(provider: str, api_key: str, model: str, desc: str) -> str:
    prompt = (
        f'Project description: "{desc or "General project"}"\n\n'
        "Generate a comprehensive .gitignore for this project's tech stack.\n"
        "Detect the language/framework from the description.\n"
        "Output ONLY the .gitignore content, no comments about what you're doing."
    )
    text, err = generate_safe(provider, api_key, model, prompt, max_tokens=600, temperature=0.2)
    return text or "# Auto-generated\n*.log\n*.env\n__pycache__/\nnode_modules/\n.DS_Store\n"


def _detect_tech_stack(idea: str) -> str:
    """Infer the likely tech stack from the idea string for better .gitignore generation."""
    idea_lower = idea.lower()
    stacks = []
    if any(w in idea_lower for w in ["python", "flask", "django", "fastapi", "scrapy", "pandas", "ml", "ai", "bot", "script", "cli"]):
        stacks.append("Python")
    if any(w in idea_lower for w in ["react", "next", "vue", "svelte", "frontend", "dashboard", "ui", "web app"]):
        stacks.append("Node/React")
    if any(w in idea_lower for w in ["node", "express", "npm", "typescript", "js", "javascript"]):
        stacks.append("Node.js")
    if any(w in idea_lower for w in ["rust", "cargo"]):
        stacks.append("Rust")
    if any(w in idea_lower for w in ["go", "golang"]):
        stacks.append("Go")
    if any(w in idea_lower for w in ["java", "spring", "maven", "gradle"]):
        stacks.append("Java")
    if any(w in idea_lower for w in ["docker", "kubernetes", "k8s", "devops", "infra"]):
        stacks.append("Docker/DevOps")
    return ", ".join(stacks) if stacks else "general"


def generate_repo_suggestion(provider: str, api_key: str, model: str, idea: str) -> dict:
    """
    Given a project idea string, return a dict with:
      name        – slug-safe repo name derived directly from the idea
      description – specific one-sentence description
      readme      – full README.md with real content based on the idea
      gitignore   – .gitignore matched to the detected tech stack
      tech_stack  – detected stack label (for display)
    Uses a structured two-call approach: first extract specifics, then generate content.
    """
    import json as _json

    stack = _detect_tech_stack(idea)

    # ── Step 1: Extract concrete specifics from the idea ──────
    # This prevents generic/random output by grounding the AI first
    extract_prompt = (
        f'A developer described this project idea: "{idea}"\n\n'
        f"Detected tech stack: {stack}\n\n"
        "Extract and infer the following as a JSON object. Be SPECIFIC to this exact idea — "
        "do not give generic answers.\n\n"
        "{\n"
        '  "repo_name": "lowercase-hyphenated-name derived directly from the idea (max 40 chars)",\n'
        '  "one_liner": "One specific sentence describing exactly what this project does (max 100 chars)",\n'
        '  "main_language": "Primary programming language",\n'
        '  "key_features": ["feature 1 specific to this project", "feature 2", "feature 3", "feature 4"],\n'
        '  "install_steps": ["step 1", "step 2", "step 3"],\n'
        '  "usage_example": "A short realistic code or CLI example showing this tool in use",\n'
        '  "gitignore_patterns": ["pattern1", "pattern2", "...all patterns for this stack"]\n'
        "}\n\n"
        "Output ONLY the raw JSON. No markdown fences, no explanation."
    )

    # Low temperature: this step extracts facts from the idea text, it should not
    # invent random/varying details each time it's called.
    spec_text, spec_err = generate_safe(provider, api_key, model, extract_prompt, max_tokens=800, temperature=0.25)

    # Parse the spec — fall back gracefully if JSON fails
    spec = {}
    if spec_text:
        clean = re.sub(r"^```(?:json)?\s*|\s*```$", "", spec_text.strip(), flags=re.MULTILINE).strip()
        try:
            spec = _json.loads(clean)
        except Exception:
            # Try to extract partial JSON
            try:
                m = re.search(r"\{.*\}", clean, re.DOTALL)
                if m:
                    spec = _json.loads(m.group())
            except Exception:
                spec = {}

    # Models sometimes return valid JSON that is not an object (a list, a
    # bare string) — normalize before touching it.
    if not isinstance(spec, dict):
        spec = {}

    # Build safe defaults from spec + idea
    raw_name = spec.get("repo_name") or re.sub(r"[^a-z0-9]+", "-", idea.lower()).strip("-")[:40]
    repo_name = re.sub(r"[^a-z0-9\-]", "", raw_name.lower().replace(" ", "-")).strip("-")[:50] or "my-project"
    one_liner = spec.get("one_liner") or idea[:100]
    language  = spec.get("main_language") or stack or "various"
    features  = spec.get("key_features") or [f"Core {idea[:30]} functionality", "Clean API", "Easy setup", "Extensible"]
    install   = spec.get("install_steps") or [f"git clone https://github.com/user/{repo_name}", "cd " + repo_name, "# install dependencies"]
    usage_ex  = spec.get("usage_example") or f"# see README for usage examples"
    gi_pats   = spec.get("gitignore_patterns") or []
    # A string here would be iterated character-by-character (e.g. into the
    # .gitignore, one character per line) — enforce list-ness.
    if not isinstance(features, list):
        features = [str(features)]
    if not isinstance(install, list):
        install = [str(install)]
    if not isinstance(gi_pats, list):
        gi_pats = []

    # ── Step 2: Generate the README from the extracted spec ───
    features_md = "\n".join(f"- {f}" for f in features[:6])
    install_md  = "\n".join(f"{i+1}. `{s}`" for i, s in enumerate(install[:5]))

    readme_prompt = (
        f'Write a professional README.md for a GitHub project called "{repo_name}".\n'
        f'Description: {one_liner}\n'
        f'Language: {language}\n'
        f'Key features:\n{features_md}\n'
        f'Install steps:\n{install_md}\n'
        f'Usage example:\n{usage_ex}\n\n'
        "Rules:\n"
        "- Use ONLY information from the description and features above — do not invent random features\n"
        "- Write in a professional but approachable tone\n"
        "- Include: # Title with emoji, short description, ## ✨ Features, ## 📦 Installation (with code block), "
        "## 🚀 Usage (with code block), ## 🤝 Contributing, ## 📄 License (MIT)\n"
        "- Output ONLY the markdown. No preamble."
    )

    readme_text, _ = generate_safe(provider, api_key, model, readme_prompt, max_tokens=1500, temperature=0.55)
    if not readme_text:
        readme_text = (
            f"# {repo_name}\n\n"
            f"{one_liner}\n\n"
            f"## ✨ Features\n\n{features_md}\n\n"
            f"## 📦 Installation\n\n```bash\n{chr(10).join(install)}\n```\n\n"
            f"## 🚀 Usage\n\n```\n{usage_ex}\n```\n\n"
            f"## 📄 License\n\nMIT\n"
        )

    # ── Step 3: Build .gitignore from detected patterns ───────
    # Use patterns from spec if available, otherwise generate from stack
    if gi_pats:
        gitignore_lines = [f"# {repo_name} — auto-generated .gitignore", ""]
        gitignore_lines.extend(gi_pats)
        gitignore_text = "\n".join(gitignore_lines)
    else:
        gi_prompt = (
            f'Project: "{repo_name}" — {one_liner}\n'
            f'Language/stack: {language}\n\n'
            "Generate a complete, accurate .gitignore for this exact stack.\n"
            "Include only patterns relevant to this stack. Output ONLY .gitignore content."
        )
        gi_text, _ = generate_safe(provider, api_key, model, gi_prompt, max_tokens=400, temperature=0.2)
        gitignore_text = gi_text or "# Auto-generated\n*.log\n*.env\n__pycache__/\nnode_modules/\n.DS_Store\n"

    return {
        "name":        repo_name,
        "description": one_liner,
        "readme":      readme_text.strip(),
        "gitignore":   gitignore_text.strip(),
        "tech_stack":  language,
        "features":    features,
    }


def generate_smart_commit_message(provider: str, api_key: str, model: str,
                                   filenames: list, description: str) -> str:
    """Generate a meaningful commit message based on files being pushed."""
    file_list = ", ".join(filenames[:20]) or "various files"
    prompt = (
        f'Project description: "{description or "No description"}"\n'
        f'Files being committed: {file_list}\n\n'
        "Write a concise, meaningful Git commit message (imperative mood, max 72 chars).\n"
        "Examples: 'Add authentication module and user schema'\n"
        "Output ONLY the commit message line. No explanation."
    )
    text, _ = generate_safe(provider, api_key, model, prompt, max_tokens=80, temperature=0.3)
    if text:
        # Take only the first line and cap length
        first = text.strip().splitlines()[0][:72]
        return first
    return "Initial commit via GitHub AI Bot"
