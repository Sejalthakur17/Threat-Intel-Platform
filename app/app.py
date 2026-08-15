"""
Threat Intelligence Feed Aggregator
Pulls live IOCs from free public sources:
  - abuse.ch URLhaus (malicious URLs)
  - Feodo Tracker (botnet C2 IPs)
  - AlienVault OTX (threat indicators)

Exposes:
  - Web dashboard at /
  - REST API at /api/check?ip=x.x.x.x
  - Prometheus metrics at /metrics
"""

import os
import time
import threading
import requests
import psycopg2
import redis
import json
import ipaddress
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

app = Flask(__name__)

# ── ENV CONFIG ─────────────────────────────────────────────────────────────
DB_HOST     = os.getenv("DB_HOST", "localhost")
DB_NAME     = os.getenv("DB_NAME", "threatintel")
DB_USER     = os.getenv("DB_USER", "sejal")
DB_PASS     = os.getenv("DB_PASS", "changeme")
REDIS_HOST  = os.getenv("REDIS_HOST", "localhost")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")          # free at otx.alienvault.com

# ── PROMETHEUS METRICS ──────────────────────────────────────────────────────
REQUEST_COUNT    = Counter("app_requests_total",    "Total HTTP requests",   ["method", "endpoint", "status"])
REQUEST_LATENCY  = Histogram("app_request_latency_seconds", "Request latency", ["endpoint"])
IOC_COUNT        = Gauge("threat_iocs_total",       "Total IOCs in database")
LAST_FETCH_TIME  = Gauge("threat_last_fetch_timestamp", "Unix timestamp of last successful feed fetch")
API_CHECKS       = Counter("threat_api_checks_total",   "Total IP/domain checks via API")
THREATS_DETECTED = Counter("threat_detections_total",   "Total positive threat detections")

# ── DATABASE ────────────────────────────────────────────────────────────────
def get_db():
    return psycopg2.connect(
        host=DB_HOST, dbname=DB_NAME,
        user=DB_USER, password=DB_PASS
    )

def init_db():
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id          SERIAL PRIMARY KEY,
            indicator   TEXT NOT NULL,
            type        VARCHAR(20) NOT NULL,   -- ip, url, domain, hash
            source      VARCHAR(50) NOT NULL,   -- abusech, feodo, otx
            threat_type TEXT,
            confidence  INTEGER DEFAULT 50,     -- 0-100
            first_seen  TIMESTAMP DEFAULT NOW(),
            last_seen   TIMESTAMP DEFAULT NOW(),
            tags        TEXT[],
            UNIQUE(indicator, source)
        );
        CREATE INDEX IF NOT EXISTS idx_indicator ON iocs(indicator);
        CREATE INDEX IF NOT EXISTS idx_type      ON iocs(type);
        CREATE INDEX IF NOT EXISTS idx_last_seen ON iocs(last_seen DESC);
    """)
    conn.commit()
    cur.close()
    conn.close()

# ── REDIS CACHE ─────────────────────────────────────────────────────────────
def get_cache():
    return redis.Redis(host=REDIS_HOST, port=6379, decode_responses=True)

# ── FEED FETCHERS ───────────────────────────────────────────────────────────
def fetch_feodo():
    """Feodo Tracker — botnet C2 IP blocklist (CSV)"""
    try:
        r = requests.get(
            "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
            timeout=15
        )
        conn = get_db()
        cur  = conn.cursor()
        count = 0
        for line in r.text.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split(",")
            if len(parts) < 3:
                continue
            ip          = parts[1].strip().strip('"')
            threat_type = parts[3].strip().strip('"') if len(parts) > 3 else "Botnet C2"
            try:
                ipaddress.ip_address(ip)   # validate
            except ValueError:
                continue
            cur.execute("""
                INSERT INTO iocs (indicator, type, source, threat_type, confidence, tags)
                VALUES (%s, 'ip', 'feodo', %s, 90, %s)
                ON CONFLICT (indicator, source) DO UPDATE
                  SET last_seen = NOW(), threat_type = EXCLUDED.threat_type
            """, (ip, threat_type, ["botnet", "c2"]))
            count += 1
        conn.commit()
        cur.close()
        conn.close()
        print(f"[Feodo] Synced {count} IPs")
        return count
    except Exception as e:
        print(f"[Feodo] Error: {e}")
        return 0

def fetch_urlhaus():
    """abuse.ch URLhaus — malicious URL blocklist (no auth needed)"""
    try:
        r = requests.get(
            "https://urlhaus.abuse.ch/downloads/text_recent/",
            timeout=15
        )
        conn  = get_db()
        cur   = conn.cursor()
        count = 0
        for line in r.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            url = line
            cur.execute("""
                INSERT INTO iocs (indicator, type, source, threat_type, confidence, tags)
                VALUES (%s, 'url', 'urlhaus', 'malware', 85, %s)
                ON CONFLICT (indicator, source) DO UPDATE
                  SET last_seen = NOW()
            """, (url, ["malware"]))
            count += 1
        conn.commit()
        cur.close()
        conn.close()
        print(f"[URLhaus] Synced {count} URLs")
        return count
    except Exception as e:
        print(f"[URLhaus] Error: {e}")
        return 0
def fetch_otx():
    """AlienVault OTX — pulse indicators (requires free API key)"""
    if not OTX_API_KEY:
        print("[OTX] No API key set — skipping")
        return 0
    try:
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        since   = (datetime.utcnow() - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S")
        r       = requests.get(
            f"https://otx.alienvault.com/api/v1/pulses/subscribed?modified_since={since}&limit=10",
            headers=headers, timeout=15
        )
        pulses = r.json().get("results", [])
        conn   = get_db()
        cur    = conn.cursor()
        count  = 0
        for pulse in pulses:
            tags = pulse.get("tags", [])
            for indicator in pulse.get("indicators", []):
                ioc_val  = indicator.get("indicator", "")
                ioc_type = indicator.get("type", "").lower()
                if ioc_type in ("ipv4", "ipv6"):
                    ioc_type = "ip"
                elif ioc_type in ("url",):
                    ioc_type = "url"
                elif ioc_type in ("domain", "hostname"):
                    ioc_type = "domain"
                elif ioc_type in ("filehash-md5", "filehash-sha1", "filehash-sha256"):
                    ioc_type = "hash"
                else:
                    continue
                cur.execute("""
                    INSERT INTO iocs (indicator, type, source, threat_type, confidence, tags)
                    VALUES (%s, %s, 'otx', %s, 75, %s)
                    ON CONFLICT (indicator, source) DO UPDATE
                      SET last_seen = NOW()
                """, (ioc_val, ioc_type, pulse.get("name", "threat"), tags))
                count += 1
        conn.commit()
        cur.close()
        conn.close()
        print(f"[OTX] Synced {count} indicators")
        return count
    except Exception as e:
        print(f"[OTX] Error: {e}")
        return 0

def sync_feeds():
    """Run all fetchers, update Prometheus gauges"""
    print(f"[Sync] Starting feed sync at {datetime.utcnow()}")
    fetch_feodo()
    fetch_urlhaus()
    fetch_otx()
    # update IOC count gauge
    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM iocs")
        total = cur.fetchone()[0]
        IOC_COUNT.set(total)
        LAST_FETCH_TIME.set(time.time())
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[Sync] Gauge update error: {e}")
    print("[Sync] Done")

def background_sync():
    """Sync every 6 hours in background thread"""
    while True:
        sync_feeds()
        time.sleep(6 * 60 * 60)

# ── ROUTES ───────────────────────────────────────────────────────────────────
@app.before_request
def start_timer():
    request._start_time = time.time()

@app.after_request
def record_metrics(response):
    latency = time.time() - getattr(request, "_start_time", time.time())
    REQUEST_COUNT.labels(request.method, request.path, response.status_code).inc()
    REQUEST_LATENCY.labels(request.path).observe(latency)
    return response

@app.route("/")
def index():
    """Main dashboard"""
    try:
        conn = get_db()
        cur  = conn.cursor()
        # recent threats
        cur.execute("""
            SELECT indicator, type, source, threat_type, confidence, last_seen
            FROM iocs ORDER BY last_seen DESC LIMIT 50
        """)
        recent = cur.fetchall()
        # stats
        cur.execute("SELECT COUNT(*) FROM iocs")
        total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM iocs WHERE last_seen > NOW() - INTERVAL '24 hours'")
        last24h = cur.fetchone()[0]
        cur.execute("SELECT source, COUNT(*) FROM iocs GROUP BY source")
        by_source = dict(cur.fetchall())
        cur.execute("SELECT type, COUNT(*) FROM iocs GROUP BY type")
        by_type = dict(cur.fetchall())
        cur.close()
        conn.close()
        return render_template("index.html",
            recent=recent, total=total,
            last24h=last24h, by_source=by_source,
            by_type=by_type,
            updated=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        )
    except Exception as e:
        return f"<h2>Starting up... ({e})</h2>", 503

@app.route("/api/check")
def check():
    """
    Check if an IP, domain, or URL is in the threat database.
    GET /api/check?ip=1.2.3.4
    GET /api/check?domain=evil.com
    GET /api/check?url=http://bad.site/malware.exe
    """
    API_CHECKS.inc()
    indicator = (
        request.args.get("ip") or
        request.args.get("domain") or
        request.args.get("url") or ""
    ).strip()

    if not indicator:
        return jsonify({"error": "Pass ?ip=, ?domain=, or ?url="}), 400

    # check cache first
    cache_key = f"check:{indicator}"
    try:
        cache = get_cache()
        cached = cache.get(cache_key)
        if cached:
            return jsonify(json.loads(cached))
    except Exception:
        pass

    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute("""
            SELECT indicator, type, source, threat_type, confidence, last_seen, tags
            FROM iocs WHERE indicator = %s
        """, (indicator,))
        rows = cur.fetchall()
        cur.close()
        conn.close()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    if rows:
        THREATS_DETECTED.inc()
        result = {
            "indicator": indicator,
            "malicious": True,
            "hits": len(rows),
            "max_confidence": max(r[4] for r in rows),
            "sources": [{"source": r[2], "threat_type": r[3],
                         "confidence": r[4], "last_seen": str(r[5]),
                         "tags": r[6]} for r in rows],
            "checked_at": datetime.utcnow().isoformat()
        }
    else:
        result = {
            "indicator": indicator,
            "malicious": False,
            "hits": 0,
            "checked_at": datetime.utcnow().isoformat()
        }

    # cache for 1 hour
    try:
        cache = get_cache()
        cache.setex(cache_key, 3600, json.dumps(result, default=str))
    except Exception:
        pass

    return jsonify(result)

@app.route("/api/stats")
def stats():
    """Quick stats endpoint"""
    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM iocs")
        total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM iocs WHERE last_seen > NOW() - INTERVAL '24 hours'")
        last24h = cur.fetchone()[0]
        cur.execute("SELECT source, COUNT(*) FROM iocs GROUP BY source")
        by_source = dict(cur.fetchall())
        cur.close()
        conn.close()
        return jsonify({
            "total_iocs": total,
            "added_last_24h": last24h,
            "by_source": by_source,
            "updated_at": datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/metrics")
def metrics():
    """Prometheus scrape endpoint"""
    return generate_latest(), 200, {"Content-Type": CONTENT_TYPE_LATEST}

@app.route("/health")
def health():
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat()})

# ── STARTUP ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    time.sleep(5)                          # wait for postgres to be ready
    init_db()
    t = threading.Thread(target=background_sync, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=5000, debug=False)
