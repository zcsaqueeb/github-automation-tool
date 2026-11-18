# syntax=docker/dockerfile:1

FROM python:3.12-slim AS base

# ── System dependencies ──────────────────────────────────────
# p7zip-full provides `7z`, used as the rarfile package's fallback
# extraction tool if the pure-Python unrar-cffi backend can't handle a
# particular RAR file. Not required for ZIP/TAR uploads.
RUN apt-get update \
    && apt-get install -y --no-install-recommends p7zip-full build-essential \
    && rm -rf /var/lib/apt/lists/*

# ── Application user (never run as root) ─────────────────────
RUN useradd --create-home --shell /usr/sbin/nologin botuser
WORKDIR /app

# ── Python dependencies (cached layer) ────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# ── Application code ───────────────────────────────────────────
COPY . .

# users.json / bot.log are written at runtime — make sure the
# non-root user can create and update them.
RUN mkdir -p /app/data \
    && chown -R botuser:botuser /app

USER botuser

# The bot uses long-polling, not a webhook — no port needs to be exposed.
ENV PYTHONUNBUFFERED=1 \
    CLI_ANIMATION=false \
    DB_FILE=/app/data/users.json \
    LOG_FILE=/app/data/bot.log

CMD ["python", "bot.py"]
