"""
cli_log.py — Redesigned CLI logger for GitHub AI Repo Bot V11
Beautiful, structured, Windows CMD + PowerShell compatible
"""

import logging
import os
import sys
import threading
import time
from datetime import datetime

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
    cfg = _LEVELS.get(level, (WH, "·", level[:6], WH))
    col, icon, label, lcol = cfg

    ts_str   = f"{DM}{_now()}{R}"
    icon_str = f"{col}{BD}{icon}{R}"
    lbl_str  = f"{lcol}{label}{R}"
    msg_str  = f"{BW}{msg}{R}"

    # main line
    line = f"  {ts_str}  {_SEPARATOR}  {icon_str}  {lbl_str}  {_SEPARATOR}  {msg_str}"
    print(line, flush=True)

    # optional detail on next line, indented
    if detail:
        pad = " " * 28
        print(f"{pad}{DM}╰─ {detail}{R}", flush=True)

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

# ── Banner ─────────────────────────────────────────────────────
def print_banner():
    W  = "\033[97m" if _USE_COLOR else ""
    LB = "\033[96m" if _USE_COLOR else ""
    LG = "\033[92m" if _USE_COLOR else ""
    LM = "\033[95m" if _USE_COLOR else ""
    LY = "\033[93m" if _USE_COLOR else ""
    B  = "\033[1m"  if _USE_COLOR else ""
    Rs = "\033[0m"  if _USE_COLOR else ""
    DI = "\033[2m"  if _USE_COLOR else ""

    border = f"{LB}{B}"
    inner  = f"{LB}{B}│{Rs}"

    print()
    print(f"  {border}╔═════════════════════════════════════════════════════╗{Rs}")
    print(f"  {inner}                                                     {inner}")
    print(f"  {inner}   {LM}{B}  ██████╗ ██╗████████╗██╗  ██╗██╗   ██╗██████╗  {Rs}   {inner}")
    print(f"  {inner}   {LM}{B} ██╔════╝ ██║╚══██╔══╝██║  ██║██║   ██║██╔══██╗ {Rs}   {inner}")
    print(f"  {inner}   {LM}{B} ██║  ███╗██║   ██║   ███████║██║   ██║██████╔╝ {Rs}   {inner}")
    print(f"  {inner}   {LM}{B} ██║   ██║██║   ██║   ██╔══██║██║   ██║██╔══██╗ {Rs}   {inner}")
    print(f"  {inner}   {LM}{B} ╚██████╔╝██║   ██║   ██║  ██║╚██████╔╝██████╔╝ {Rs}   {inner}")
    print(f"  {inner}   {LM}{B}  ╚═════╝ ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═════╝  {Rs}   {inner}")
    print(f"  {inner}                                                     {inner}")
    print(f"  {border}╠═════════════════════════════════════════════════════╣{Rs}")
    print(f"  {inner}   {LY}{B}🚀  AI Repo Bot  {DI}·{Rs}  {LG}{B}GitHub Manager for Telegram{Rs}      {inner}")
    print(f"  {inner}                                                     {inner}")
    print(f"  {inner}   {W}{B}Version   {LG}V29.0.0{Rs}                                  {inner}")
    print(f"  {inner}   {W}{B}Creator   {LM}Saqueeb{Rs}                                  {inner}")
    print(f"  {inner}   {W}{B}AI        {LG}Multi-Provider · Groq Free{Rs}               {inner}")
    print(f"  {inner}   {W}{B}Platform  {LY}Telegram Bot API{Rs}                         {inner}")
    print(f"  {inner}                                                     {inner}")
    print(f"  {border}╠═════════════════════════════════════════════════════╣{Rs}")
    print(f"  {inner}   {DI}Started   {Rs}{W}{_now()}  ·  {_date()}{Rs}                    {inner}")
    print(f"  {border}╚═════════════════════════════════════════════════════╝{Rs}")
    print()
    divider("STARTUP")
    print()

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
        fn(record.getMessage())

def setup_file_logger(path: str = "bot.log") -> logging.Logger:
    """Returns a file-only logger for persisting all logs."""
    flog = logging.getLogger("BotFile")
    flog.setLevel(logging.DEBUG)
    if not flog.handlers:
        h = logging.FileHandler(path, encoding="utf-8")
        h.setFormatter(logging.Formatter(
            "%(asctime)s  [%(levelname)-8s]  %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        flog.addHandler(h)
    return flog
