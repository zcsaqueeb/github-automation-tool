"""
cli_log.py — Redesigned CLI logger for GitHub AI Repo Bot
Beautiful, structured, Windows CMD + PowerShell compatible.

Adds an optional 🌸 anime-style boot animation (truecolor sakura→ice
gradient logo, typewriter init line, filling progress bar + spinner→✓ boot
lines, and a kawaii "ONLINE!" flourish). Auto-degrades to a clean static
banner on non-TTY (Railway/Docker/log files) so logs stay readable.

Env toggles:
  CLI_ANIMATION   = true|false   (default true)  — enable/disable animation
  CLI_ANIM_SPEED  = float         (default 1.0)   — lower = faster
  CLI_USER_LOG_TTL = seconds      (default 10)    — hide latest USER activity line
"""

import logging
import os
import re
import sys
import threading
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler


def _make_streams_utf8() -> None:
    """Force stdout/stderr to UTF-8 so the banner's box-drawing glyphs and
    emoji never raise UnicodeEncodeError on a legacy Windows console/pipe
    (which defaults to cp1252). Falls back to a byte-level wrapper when the
    stream can't be reconfigured, and to lossy replacement as a last resort."""
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        if stream is None:
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
            continue
        except Exception:
            pass
        try:
            import io
            buffer = getattr(stream, "buffer", None)
            if buffer is not None:
                wrapped = io.TextIOWrapper(
                    buffer, encoding="utf-8", errors="replace", line_buffering=True
                )
                setattr(sys, name, wrapped)
        except Exception:
            pass


_make_streams_utf8()

# ── ANSI support detection ──────────────────────────────────────
def _ansi_supported() -> bool:
    """True if the terminal supports ANSI escape codes."""
    if os.name == "nt":
        # Enable VT100 on Windows 10+
        try:
            import ctypes
            kernel = ctypes.windll.kernel32
            kernel.SetConsoleMode(kernel.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

_USE_COLOR = _ansi_supported()

# ── TTY / animation detection ──────────────────────────────────
def _is_tty() -> bool:
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False

def _env_flag(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() not in ("0", "false", "no", "off", "")

def _truecolor_supported() -> bool:
    """24-bit color: Windows 10+ (VT enabled above) or COLORTERM hint."""
    if not _USE_COLOR:
        return False
    if os.name == "nt":
        return True
    return os.environ.get("COLORTERM", "").lower() in ("truecolor", "24bit")

# Animation is on only when explicitly allowed AND we're on a real TTY with color.
_ANIM = _env_flag("CLI_ANIMATION", True) and _is_tty() and _USE_COLOR
_THEME = os.environ.get("CLI_THEME", "cyber").strip().lower()
try:
    _USER_LOG_TTL = max(0, float(os.environ.get("CLI_USER_LOG_TTL", "10")))
except ValueError:
    _USER_LOG_TTL = 10.0
_console_lock = threading.Lock()
_console_generation = 0
try:
    _ANIM_SPEED = max(0.05, float(os.environ.get("CLI_ANIM_SPEED", "1.0")))
except Exception:
    _ANIM_SPEED = 1.0

def _nap(seconds: float) -> None:
    """Sleep scaled by CLI_ANIM_SPEED (lower speed value = faster)."""
    if _ANIM and seconds > 0:
        time.sleep(seconds * _ANIM_SPEED)

# ── ANSI codes (only applied when supported) ───────────────────
R  = "\033[0m"    if _USE_COLOR else ""   # reset
BD = "\033[1m"    if _USE_COLOR else ""   # bold
DM = "\033[2m"    if _USE_COLOR else ""   # dim

BK = "\033[30m"   if _USE_COLOR else ""   # black
RE = "\033[31m"   if _USE_COLOR else ""   # red
GR = "\033[32m"   if _USE_COLOR else ""   # green
YL = "\033[33m"   if _USE_COLOR else ""   # yellow
BL = "\033[34m"   if _USE_COLOR else ""   # blue
MG = "\033[35m"   if _USE_COLOR else ""   # magenta
CY = "\033[36m"   if _USE_COLOR else ""   # cyan
WH = "\033[37m"   if _USE_COLOR else ""   # white

BR = "\033[91m"   if _USE_COLOR else ""   # bright red
BG = "\033[92m"   if _USE_COLOR else ""   # bright green
BY = "\033[93m"   if _USE_COLOR else ""   # bright yellow
BB = "\033[94m"   if _USE_COLOR else ""   # bright blue
BM = "\033[95m"   if _USE_COLOR else ""   # bright magenta
BC = "\033[96m"   if _USE_COLOR else ""   # bright cyan
BW = "\033[97m"   if _USE_COLOR else ""   # bright white

BGRE = "\033[41m" if _USE_COLOR else ""   # bg red
BGGE = "\033[42m" if _USE_COLOR else ""   # bg green
BGYE = "\033[43m" if _USE_COLOR else ""   # bg yellow

# ── Truecolor helpers (24-bit gradient) ────────────────────────
_TRUECOLOR = _truecolor_supported()

def _fg(r: int, g: int, b: int) -> str:
    return f"\033[38;2;{r};{g};{b}m" if _TRUECOLOR else ""

def _lerp(a, b, t):
    return tuple(int(round(a[i] + (b[i] - a[i]) * t)) for i in range(3))

# sakura pink → ice cyan
_GRAD_A = (255, 145, 195)   # sakura
_GRAD_B = (130, 220, 255)   # ice

def _grad_color(t: float) -> str:
    """Return a truecolor escape along the sakura→ice gradient (t in 0..1)."""
    return _fg(*_lerp(_GRAD_A, _GRAD_B, max(0.0, min(1.0, t))))

# ── Level definitions ──────────────────────────────────────────
#   (color, icon, label, label_color)
_LEVELS = {
    "DEBUG":    (DM+WH,   "·",  "DEBUG ",  DM+WH),
    "INFO":     (BC,      "ℹ",  "INFO  ",  BC+BD),
    "SUCCESS":  (BG,      "✔",  "OK    ",  BG+BD),
    "WARNING":  (BY,      "⚠",  "WARN  ",  BY+BD),
    "ERROR":    (BR,      "✖",  "ERROR ",  BR+BD),
    "CRITICAL": (BGRE+BW, "✖✖", "FATAL ",  BGRE+BW+BD),
    "EVENT":    (BM,      "◆",  "EVENT ",  BM+BD),
    "USER":     (BB,      "👤", "USER  ",  BB+BD),
    "AI":       (BC,      "🤖", "AI    ",  BC+BD),
    "GITHUB":   (BG,      "🐙", "GITHUB",  BG+BD),
}

_SEPARATOR = f"{DM}│{R}"

def _now() -> str:
    return datetime.now().strftime("%H:%M:%S")

def _date() -> str:
    return datetime.now().strftime("%d %b %Y")

# ── Core print ─────────────────────────────────────────────────
def _print(level: str, msg: str, detail: str = "") -> None:
    global _console_generation
    cfg = _LEVELS.get(level, (WH, "·", level[:6], WH))
    col, icon, label, lcol = cfg

    msg    = _redact(msg)
    detail = _redact(detail) if detail else detail

    ts_str   = f"{DM}{_now()}{R}"
    icon_str = f"{col}{BD}{icon}{R}"
    lbl_str  = f"{lcol}{label}{R}"
    msg_str  = f"{BW}{msg}{R}"

    # main line
    line = f"  {ts_str}  {_SEPARATOR}  {icon_str}  {lbl_str}  {_SEPARATOR}  {msg_str}"
    with _console_lock:
        _console_generation += 1
        generation = _console_generation
        print(line, flush=True)
        # optional detail on next line, indented — kept inside the lock so
        # two threads cannot interleave detail under the wrong log line
        if detail:
            pad = " " * 28
            print(f"{pad}{DM}╰─ {detail}{R}", flush=True)

    # User activity (for example, /start) is useful live but need not remain
    # on screen. Only erase it when no newer output exists; otherwise moving
    # the cursor would corrupt a later log line. File logs are unaffected.
    if level == "USER" and _USER_LOG_TTL > 0 and _is_tty() and _USE_COLOR:
        line_count = 2 if detail else 1
        def _expire() -> None:
            global _console_generation
            with _console_lock:
                if generation != _console_generation:
                    return
                for _ in range(line_count):
                    sys.stdout.write("\033[1A\r\033[2K")
                sys.stdout.flush()
                _console_generation += 1
        timer = threading.Timer(_USER_LOG_TTL, _expire)
        timer.daemon = True
        timer.start()

# ── Section divider ────────────────────────────────────────────
def divider(title: str = "") -> None:
    width = 60
    if title:
        t = f"  {title}  "
        left  = (width - len(t)) // 2
        right = width - len(t) - left
        line  = f"{DM}{'─'*left}{R}{BY+BD}{t}{R}{DM}{'─'*right}{R}"
    else:
        line = f"{DM}{'─'*width}{R}"
    print(f"  {line}", flush=True)

# ── Public log functions ───────────────────────────────────────
def debug(msg: str,    detail: str = ""): _print("DEBUG",    msg, detail)
def info(msg: str,     detail: str = ""): _print("INFO",     msg, detail)
def ok(msg: str,       detail: str = ""): _print("SUCCESS",  msg, detail)
def warn(msg: str,     detail: str = ""): _print("WARNING",  msg, detail)
def error(msg: str,    detail: str = ""): _print("ERROR",    msg, detail)
def critical(msg: str, detail: str = ""): _print("CRITICAL", msg, detail)
def event(msg: str,    detail: str = ""): _print("EVENT",    msg, detail)
def user(msg: str,     detail: str = ""): _print("USER",     msg, detail)
def ai(msg: str,       detail: str = ""): _print("AI",       msg, detail)
def github(msg: str,   detail: str = ""): _print("GITHUB",   msg, detail)

# ── Spinner ────────────────────────────────────────────────────
class Spinner:
    FRAMES = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

    def __init__(self, label: str):
        self.label   = label
        self._stop   = threading.Event()
        self._thread = threading.Thread(target=self._spin, daemon=True)

    def _spin(self):
        i = 0
        while not self._stop.is_set():
            frame = f"{BC}{BD}{self.FRAMES[i % len(self.FRAMES)]}{R}"
            ts    = f"{DM}{_now()}{R}"
            print(f"\r  {ts}  {_SEPARATOR}  {frame}  {DM}{self.label}...{R}",
                  end="", flush=True)
            time.sleep(0.1)
            i += 1

    def start(self):   self._thread.start(); return self
    def stop(self, success: bool = True, msg: str = ""):
        self._stop.set(); self._thread.join()
        print("\r" + " " * 80 + "\r", end="", flush=True)
        if msg: (ok if success else error)(msg)
    def __enter__(self): return self.start()
    def __exit__(self, *_): self.stop()

# ── Banner config (single source of truth) ─────────────────────
APP_CREATOR = "Saqueeb"

# Block-letter logo for GITHUB (6 rows). Rendered with a per-row gradient
# when truecolor + animation is available; falls back to magenta otherwise.
_LOGO_ROWS = [
    "  ██████╗ ██╗████████╗██╗  ██╗██╗   ██╗██████╗ ",
    " ██╔════╝ ██║╚══██╔══╝██║  ██║██║   ██║██╔══██╗ ",
    " ██║  ███╗██║   ██║   ███████║██║   ██║██████╔╝ ",
    " ██║   ██║██║   ██║   ██╔══██║██║   ██║██╔══██╗ ",
    " ╚██████╔╝██║   ██║   ██║  ██║╚██████╔╝██████╔╝ ",
    "  ╚═════╝ ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═════╝  ",
]

def _typewriter(text: str, color: str = "", delay: float = 0.02) -> None:
    """Print text char-by-char when animating, else all at once."""
    if not _ANIM:
        print(f"  {color}{text}{R}", flush=True)
        return
    sys.stdout.write("  ")
    for ch in text:
        sys.stdout.write(f"{color}{ch}{R}")
        sys.stdout.flush()
        _nap(delay)
    sys.stdout.write("\n")
    sys.stdout.flush()

def _print_logo() -> None:
    """Render the GITHUB logo. Animated reveal + gradient when enabled."""
    LM = "\033[95m\033[1m" if _USE_COLOR else ""   # fallback magenta bold
    Rs = R
    n = len(_LOGO_ROWS)
    for idx, row in enumerate(_LOGO_ROWS):
        if _TRUECOLOR:
            line = f"  {BD}{_grad_color(idx / max(1, n - 1))}{row}{Rs}"
        else:
            line = f"  {LM}{row}{Rs}"
        print(line, flush=True)
        _nap(0.05)

def _progress_bar(label: str, width: int = 24, duration: float = 0.7) -> None:
    """Animated filling progress bar; static full bar when not animating."""
    BAR = "▰"
    EMPTY = "▱"
    if not _ANIM:
        print(f"  {BC}{BD}[{BAR*width}]{R}  {DM}{label}{R}", flush=True)
        return
    steps = width
    for s in range(steps + 1):
        bar = f"{BC}{BD}{BAR*s}{DM}{EMPTY*(width-s)}{R}"
        sys.stdout.write(f"\r  {BC}{BD}[{bar}{BC}{BD}]{R}  {DM}{label}{R}")
        sys.stdout.flush()
        _nap(duration / steps)
    sys.stdout.write("\n")
    sys.stdout.flush()

def _boot_step(label: str, status: str = "online", spin_time: float = 0.35) -> None:
    """Spinner that resolves to a ✓ tick for a boot line."""
    if not _ANIM:
        print(f"  {BG}{BD}✓{R}  {BW}{label}{R} {DM}...{R} {BG}{status}{R}", flush=True)
        return
    frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    t0 = time.time()
    i = 0
    while (time.time() - t0) < (spin_time * _ANIM_SPEED):
        fr = frames[i % len(frames)]
        sys.stdout.write(f"\r  {BC}{BD}{fr}{R}  {BW}{label}{R} {DM}...{R}")
        sys.stdout.flush()
        time.sleep(0.06)
        i += 1
    sys.stdout.write(f"\r  {BG}{BD}✓{R}  {BW}{label}{R} {DM}...{R} {BG}{status}{R}    \n")
    sys.stdout.flush()

# ── Banner ─────────────────────────────────────────────────────
def print_banner():
    """🌸 Anime boot sequence on a TTY; clean static banner otherwise.

    Honors CLI_ANIMATION (default on) and CLI_ANIM_SPEED (default 1.0).
    On Railway/Docker/log files (non-TTY) prints a static banner with no
    escape soup so logs stay readable.
    """
    if _THEME == "cyber":
        print()
        print(f"  {BC}{BD}┌──[ GITHUB-AI-REPO-BOT ]──[ SECURE TERMINAL ]──┐{R}")
        print(f"  {BC}{BD}│{R} {BG}STATUS: ONLINE{R}  {CY}MODE: POLLING{R}  {DM}LOG: REDACTED{R} {BC}{BD}│{R}")
        print(f"  {BC}{BD}└─────────────────────────────────────────────┘{R}")
        divider("SYSTEM BOOT")
        return
    W  = "\033[97m" if _USE_COLOR else ""
    LB = "\033[96m" if _USE_COLOR else ""
    LG = "\033[92m" if _USE_COLOR else ""
    LM = "\033[95m" if _USE_COLOR else ""
    LY = "\033[93m" if _USE_COLOR else ""
    B  = "\033[1m"  if _USE_COLOR else ""
    Rs = "\033[0m"  if _USE_COLOR else ""
    DI = "\033[2m"  if _USE_COLOR else ""

    inner = f"{LB}{B}│{Rs}"

    print()
    print(f"  {LB}{B}╔═════════════════════════════════════════════════════╗{Rs}")
    print(f"  {inner}                                                     {inner}")
    # ── logo (animated gradient reveal when enabled) ──
    _print_logo()
    print(f"  {inner}                                                     {inner}")
    print(f"  {LB}{B}╠═════════════════════════════════════════════════════╣{Rs}")
    print(f"  {inner}   {LY}{B}🚀  AI Repo Bot  {DI}·{Rs}  {LG}{B}GitHub Manager for Telegram{Rs}      {inner}")
    print(f"  {inner}                                                     {inner}")
    print(f"  {inner}   {W}{B}Creator   {LM}{APP_CREATOR}{Rs}                                  {inner}")
    print(f"  {inner}   {W}{B}AI        {LG}Multi-Provider · Groq Free{Rs}               {inner}")
    print(f"  {inner}   {W}{B}Platform  {LY}Telegram Bot API{Rs}                         {inner}")
    print(f"  {inner}                                                     {inner}")
    print(f"  {LB}{B}╠═════════════════════════════════════════════════════╣{Rs}")
    print(f"  {inner}   {DI}Started   {Rs}{W}{_now()}  ·  {_date()}{Rs}                    {inner}")
    print(f"  {LB}{B}╚═════════════════════════════════════════════════════╝{Rs}")
    print()

    # ── kawaii init + boot sequence ──
    _typewriter("( ｡•̀ᵗ-)✧  systems initializing...", color=f"{BM}{BD}", delay=0.018)
    print()
    _progress_bar("loading core modules", width=24, duration=0.7)
    _boot_step("config & secrets", "loaded")
    _boot_step("ai providers",     "ready")
    _boot_step("github api",       "armed")
    print()
    divider("STARTUP")
    print()

# ── ONLINE flourish (call once Telegram is connected) ──────────
def online(username: str = "") -> None:
    """Kawaii 'ONLINE!' flourish. Plain success line when not animating."""
    tag = f"@{username}" if username else ""
    if not _ANIM:
        ok(f"🌸 ONLINE! {tag}".rstrip())
        return
    face = "ヽ(◕ヮ◕)ﾉ"
    text = "O N L I N E !"
    print()
    # gentle gradient sweep on the flourish
    if _TRUECOLOR:
        line = f"     {BD}{_grad_color(0.15)}{face}  {_grad_color(0.85)}{text}{R}"
    else:
        line = f"     {BG}{BD}{face}  {text}{R}"
    # quick blink
    for _ in range(2):
        sys.stdout.write("\r     " + " " * 40)
        sys.stdout.flush(); _nap(0.08)
        sys.stdout.write("\r" + line)
        sys.stdout.flush(); _nap(0.12)
    print()
    if tag:
        print(f"     {DM}connected as {R}{BC}{BD}{tag}{R}", flush=True)
    print()

# ── Secret redaction (defense in depth) ────────────────────────
# Applied to every log record — console and file — regardless of which
# code path produced it. Call-site discipline (never logging a raw token)
# is the primary defense; this filter is the backstop for anything that
# slips through, including third-party library log lines (e.g. a future
# telebot version, or a new AI provider's HTTP client) that this project
# doesn't directly control.
_REDACT_PATTERNS = [
    # GitHub personal access tokens (classic + fine-grained) and OAuth tokens
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    # Common AI provider key prefixes
    re.compile(r"sk-ant-[A-Za-z0-9\-_]{10,}"),
    re.compile(r"sk-proj-[A-Za-z0-9\-_]{10,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"gsk_[A-Za-z0-9]{20,}"),
    re.compile(r"AIza[A-Za-z0-9\-_]{20,}"),
    # Telegram bot tokens (digits:token)
    re.compile(r"\b\d{6,12}:[A-Za-z0-9_-]{30,}"),
    # JWTs and HTTP authorization headers frequently appear in exception text.
    re.compile(r"(?i)\b(?:authorization|bearer)\s*[: ]\s*bearer?\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    # Credential-bearing database URLs.
    re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s@]+@[^\s]+"),
    # Fernet keys (44-char urlsafe-base64 ending in =)
    re.compile(r"\b[A-Za-z0-9\-_]{43}="),
    # Generic key=value / token=value / password=value in free text
    re.compile(r"(?i)\b(api[_-]?key|token|password|secret)\b\s*[:=]\s*\S+"),
]


def _redact(text: str) -> str:
    text = str(text)
    for pat in _REDACT_PATTERNS:
        text = pat.sub("[REDACTED]", text)
    return text


def mask_user_id(user_id, name: str = "") -> str:
    """Return a readable log tag: first word of the display name plus the
    outer digits of the id, so lines stay correlatable without a full id."""
    sid    = str(user_id)
    id_tag = f"{sid[:4]}..{sid[-4:]}" if len(sid) > 8 else sid
    words  = (name or "").split()
    word   = words[0] if words else ""
    return f"{word} {id_tag}".strip()


class _RedactingFilter(logging.Filter):
    """Rewrites a LogRecord's message in place so redaction happens exactly
    once, before any handler (console or file) formats and emits it."""
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = _redact(record.getMessage())
            record.args = ()
        except Exception:
            pass
        return True


# ── Python logging bridge (captures telebot internals) ────────
class CLIHandler(logging.Handler):
    MAPPING = {
        logging.DEBUG:    debug,
        logging.INFO:     info,
        logging.WARNING:  warn,
        logging.ERROR:    error,
        logging.CRITICAL: critical,
    }
    def emit(self, record: logging.LogRecord):
        fn = self.MAPPING.get(record.levelno, info)
        fn(_redact(record.getMessage()))

def setup_file_logger(path: str = "bot.log", level: str = "INFO") -> logging.Logger:
    """Returns a file-only logger for persisting all logs.
    All records passed to this logger — from this project or any
    third-party library sharing the stdlib logging tree (e.g. telebot,
    urllib3) — are redacted for secret-shaped substrings before being
    written to disk."""
    flog = logging.getLogger("BotFile")
    numeric_level = getattr(logging, str(level).upper(), logging.INFO)
    flog.setLevel(numeric_level)
    flog.addFilter(_RedactingFilter())
    if not flog.handlers:
        # Prevent an unattended bot from consuming the disk indefinitely.
        h = RotatingFileHandler(path, maxBytes=5 * 1024 * 1024, backupCount=5,
                                encoding="utf-8")
        h.setLevel(numeric_level)
        h.setFormatter(logging.Formatter(
            "%(asctime)s  [%(levelname)-8s]  %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        # Records from third-party loggers (telebot, urllib3) propagate
        # directly to this handler, bypassing logger-attached filters — the
        # redactor MUST live on the handler to catch those.
        h.addFilter(_RedactingFilter())
        flog.addHandler(h)
    flog.propagate = False
    return flog
