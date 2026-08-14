# ── Stage 1: build deps ──────────────────────────────────────────────────────
FROM python:3.11-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM python:3.11-slim
WORKDIR /app

# non-root user for security
RUN useradd -m -u 1000 appuser

COPY --from=builder /install /usr/local
COPY . .

RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 5000

# gunicorn: production WSGI server (not flask dev server)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2",
     "--timeout", "60", "--access-logfile", "-", "app:app"]
