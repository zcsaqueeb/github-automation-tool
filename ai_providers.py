"""
ai_providers.py — Multi-provider AI integration for GitHub AI Repo Bot V9

Supported providers (all have free tiers):
  groq      — Groq API  (llama-3.3-70b-versatile, gemma2-9b-it, etc.)  FREE
  gemini    — Google Gemini (gemini-2.5-flash, gemini-1.5-flash)         FREE
  together  — Together AI  (llama-3-8b, mistral-7b, etc.)               FREE
  mistral   — Mistral AI   (mistral-small, open-mistral-7b)              FREE tier
  openai    — OpenAI        (gpt-4o-mini, gpt-3.5-turbo)                 PAID
"""

from __future__ import annotations

from typing import Optional
import requests

# ── Provider registry ──────────────────────────────────────────

PROVIDERS: dict[str, dict] = {
    "groq": {
        "name":    "Groq",
        "emoji":   "⚡",
        "free":    True,
        "url":     "https://api.groq.com/openai/v1/chat/completions",
        "style":   "openai_compat",
        "models": [
            "llama-3.3-70b-versatile",     # best quality, free
            "llama-3.1-8b-instant",        # fastest, free
            "llama3-8b-8192",
            "llama3-70b-8192",
            "gemma2-9b-it",
            "mixtral-8x7b-32768",
        ],
        "default": "llama-3.3-70b-versatile",
        "get_key": "console.groq.com/keys",
    },
    "gemini": {
        "name":    "Google Gemini",
        "emoji":   "✨",
        "free":    True,
        "url":     "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        "style":   "gemini",
        "models": [
            "gemini-2.5-flash",
            "gemini-2.5-pro",
            "gemini-1.5-flash",
            "gemini-1.5-pro",
            "gemini-1.0-pro",
        ],
        "default": "gemini-2.5-flash",
        "get_key": "aistudio.google.com/apikey",
    },
    "together": {
        "name":    "Together AI",
        "emoji":   "🤝",
        "free":    True,
        "url":     "https://api.together.xyz/v1/chat/completions",
        "style":   "openai_compat",
        "models": [
            "meta-llama/Llama-3-8b-chat-hf",
            "meta-llama/Llama-3-70b-chat-hf",
            "mistralai/Mistral-7B-Instruct-v0.2",
            "google/gemma-2-9b-it",
            "Qwen/Qwen2-72B-Instruct",
        ],
        "default": "meta-llama/Llama-3-8b-chat-hf",
        "get_key": "api.together.ai",
    },
    "mistral": {
        "name":    "Mistral AI",
        "emoji":   "🌀",
        "free":    False,
        "url":     "https://api.mistral.ai/v1/chat/completions",
        "style":   "openai_compat",
        "models": [
            "mistral-small-latest",
            "open-mistral-7b",
            "open-mixtral-8x7b",
            "mistral-medium-latest",
        ],
        "default": "mistral-small-latest",
        "get_key": "console.mistral.ai/api-keys",
    },
    "openai": {
        "name":    "OpenAI",
        "emoji":   "🧠",
        "free":    False,
        "url":     "https://api.openai.com/v1/chat/completions",
        "style":   "openai_compat",
        "models": [
            "gpt-4o-mini",
            "gpt-4o",
            "gpt-3.5-turbo",
            "gpt-4-turbo",
        ],
        "default": "gpt-4o-mini",
        "get_key": "platform.openai.com/api-keys",
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
    raw = body.get("error", {})
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
) -> str:
    """
    Call AI and return the response text.
    Raises AIError on any failure (never returns None).
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
            return _call_openai_compat(provider, api_key, model, prompt, max_tokens, timeout)
        elif info["style"] == "gemini":
            return _call_gemini(api_key, model, prompt, timeout)
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
) -> str:
    url = PROVIDERS[provider]["url"]
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type":  "application/json",
    }
    body = {
        "model":      model,
        "messages":   [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": 0.7,
    }
    r = requests.post(url, headers=headers, json=body, timeout=timeout)

    if r.status_code != 200:
        try:
            err_body = r.json()
        except Exception:
            err_body = {}
        raise _diagnose_http(r.status_code, err_body, provider)

    try:
        content = r.json()["choices"][0]["message"]["content"]
        if not content or not content.strip():
            raise AIError("empty_response", f"⚠️ {provider} returned an empty response.")
        return content.strip()
    except (KeyError, IndexError) as e:
        raise AIError("parse_error", f"❌ Couldn't parse {provider} response: `{e}`")


def _call_gemini(api_key: str, model: str, prompt: str, timeout: int) -> str:
    url = PROVIDERS["gemini"]["url"].format(model=model)
    params = {"key": api_key}
    body   = {"contents": [{"parts": [{"text": prompt}]}]}

    r = requests.post(url, params=params, json=body, timeout=timeout)

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

        content = candidates[0]["content"]["parts"][0]["text"]
        if not content.strip():
            raise AIError("empty_response", "⚠️ Gemini returned empty text.")
        return content.strip()
    except AIError:
        raise
    except (KeyError, IndexError) as e:
        raise AIError("parse_error", f"❌ Couldn't parse Gemini response: `{e}`")


# ── Safe wrapper (returns None instead of raising) ─────────────

def generate_safe(
    provider: str,
    api_key:  str,
    model:    str,
    prompt:   str,
    max_tokens: int = 1500,
) -> tuple[Optional[str], Optional[str]]:
    """Returns (text, error_message). error_message is None on success."""
    try:
        return generate(provider, api_key, model, prompt, max_tokens), None
    except AIError as e:
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
    text, err = generate_safe(provider, api_key, model, prompt, max_tokens=600)
    return text or "# Auto-generated\n*.log\n*.env\n__pycache__/\nnode_modules/\n.DS_Store\n"
