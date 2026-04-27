# database.py — SQLite database layer for WMS local server

import sqlite3
import time
import json
import threading
from config import DB_PATH

_lock = threading.Lock()


def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _lock:
        conn = get_conn()
        # WAL mode allows concurrent reads during writes and avoids an fsync
        # per commit — dramatically faster on Raspberry Pi SD cards.
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        c = conn.cursor()

        # Full event history
        c.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_ms        INTEGER NOT NULL,
                anchor_id    INTEGER NOT NULL,
                type         TEXT    NOT NULL,
                tag_uid      INTEGER,
                dist_cm      INTEGER,
                payload_json TEXT,
                mqtt_sent    INTEGER DEFAULT 0
            )
        """)

        # Latest state per tag
        c.execute("""
            CREATE TABLE IF NOT EXISTS tag_state (
                uid              INTEGER PRIMARY KEY,
                nearest_anchor   INTEGER,
                dist_cm          INTEGER,
                gear             INTEGER,
                escort           INTEGER DEFAULT 0,
                last_seen_ms     INTEGER
            )
        """)

        # Latest door state per anchor
        c.execute("""
            CREATE TABLE IF NOT EXISTS door_state (
                anchor_id   INTEGER PRIMARY KEY,
                locked      INTEGER DEFAULT 0,
                fire        INTEGER DEFAULT 0,
                rex         INTEGER DEFAULT 0,
                ajar        INTEGER DEFAULT 0,
                ts_ms       INTEGER
            )
        """)

        # Known anchors
        c.execute("""
            CREATE TABLE IF NOT EXISTS anchors (
                anchor_id        INTEGER PRIMARY KEY,
                anchor_type      INTEGER,
                location_label   TEXT    DEFAULT 'Unknown',
                last_heartbeat_ms INTEGER,
                uptime_s         INTEGER DEFAULT 0,
                online           INTEGER DEFAULT 0,
                boot_count       INTEGER DEFAULT 0
            )
        """)

        # Per-door configuration (pushed from cloud portal to anchor)
        c.execute("""
            CREATE TABLE IF NOT EXISTS anchor_config (
                anchor_id              INTEGER PRIMARY KEY,
                rex_duration_ms        INTEGER DEFAULT 3000,
                relay_hold_ms          INTEGER DEFAULT 500,
                door_ajar_timeout_ms   INTEGER DEFAULT 30000,
                signal_loss_timeout_ms INTEGER DEFAULT 60000,
                signal_loss_mode       TEXT    DEFAULT 'LOCK',
                buzzer_enable          INTEGER DEFAULT 1,
                buzzer_duration_ms     INTEGER DEFAULT 1000,
                tz                     TEXT    DEFAULT '+0:00',
                config_status          TEXT    DEFAULT 'DEFAULT',
                updated_ms             INTEGER
            )
        """)

        # Anchor certificate ledger — serial number registry for mTLS revocation
        c.execute("""
            CREATE TABLE IF NOT EXISTS anchor_certs (
                serial_hex   TEXT    PRIMARY KEY,
                anchor_id    INTEGER NOT NULL,
                issued_ms    INTEGER NOT NULL,
                revoked      INTEGER DEFAULT 0
            )
        """)

        # Firmware image registry — uploaded .bin files available for OTA
        c.execute("""
            CREATE TABLE IF NOT EXISTS firmware_files (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                filename    TEXT    NOT NULL,
                version     TEXT    NOT NULL,
                size_bytes  INTEGER NOT NULL,
                sha256      TEXT    NOT NULL,
                uploaded_ms INTEGER NOT NULL
            )
        """)

        # Migrations — add columns introduced after initial deployment
        for migration in [
            "ALTER TABLE anchor_config ADD COLUMN tz TEXT DEFAULT '+0:00'",
            "ALTER TABLE anchor_config ADD COLUMN wifi_networks TEXT DEFAULT '[]'",
            "ALTER TABLE anchor_config ADD COLUMN wifi_count INTEGER DEFAULT 0",
            "ALTER TABLE anchors ADD COLUMN boot_count INTEGER DEFAULT 0",
            "ALTER TABLE anchors ADD COLUMN fw_version  TEXT    DEFAULT NULL",
            "ALTER TABLE anchors ADD COLUMN ota_status  TEXT    DEFAULT 'IDLE'",
            "ALTER TABLE anchors ADD COLUMN ota_percent INTEGER DEFAULT 0",
        ]:
            try:
                c.execute(migration)
            except sqlite3.OperationalError:
                pass  # Column already exists

        conn.commit()
        conn.close()
        print("[DB] Initialised")


def insert_event(evt: dict) -> int:
    """Insert a raw event dict. Returns the new row id."""
    with _lock:
        conn = get_conn()
        c = conn.cursor()
        c.execute("""
            INSERT INTO events (ts_ms, anchor_id, type, tag_uid, dist_cm, payload_json)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            evt.get("ts_ms", int(time.time() * 1000)),
            evt.get("anchor_id", 0),
            evt.get("type", "UNKNOWN"),
            evt.get("tag_uid"),
            evt.get("dist_cm"),
            json.dumps(evt),
        ))
        row_id = c.lastrowid
        conn.commit()
        conn.close()
        return row_id


def upsert_anchor(anchor_id: int, anchor_type: int = None, boot_count: int = None):
    with _lock:
        conn = get_conn()
        conn.execute("""
            INSERT INTO anchors (anchor_id, anchor_type, last_heartbeat_ms, online)
            VALUES (?, ?, ?, 1)
            ON CONFLICT(anchor_id) DO UPDATE SET
                last_heartbeat_ms = excluded.last_heartbeat_ms,
                online = 1,
                anchor_type = COALESCE(excluded.anchor_type, anchor_type)
        """, (anchor_id, anchor_type, int(time.time() * 1000)))
        if boot_count is not None:
            conn.execute(
                "UPDATE anchors SET boot_count = ? WHERE anchor_id = ?",
                (boot_count, anchor_id)
            )
        conn.commit()
        conn.close()


def upsert_tag_state(uid: int, anchor_id: int, dist_cm: int,
                     gear: int = None, escort: int = 0):
    with _lock:
        conn = get_conn()
        conn.execute("""
            INSERT INTO tag_state (uid, nearest_anchor, dist_cm, gear, escort, last_seen_ms)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(uid) DO UPDATE SET
                nearest_anchor = excluded.nearest_anchor,
                dist_cm        = excluded.dist_cm,
                gear           = COALESCE(excluded.gear, gear),
                escort         = excluded.escort,
                last_seen_ms   = excluded.last_seen_ms
        """, (uid, anchor_id, dist_cm, gear, escort, int(time.time() * 1000)))
        conn.commit()
        conn.close()


def upsert_door_state(anchor_id: int, **kwargs):
    with _lock:
        conn = get_conn()
        # Build dynamic SET clause from kwargs
        fields = {k: v for k, v in kwargs.items()
                  if k in ("locked", "fire", "rex", "ajar")}
        fields["ts_ms"] = int(time.time() * 1000)

        conn.execute("""
            INSERT INTO door_state (anchor_id, locked, fire, rex, ajar, ts_ms)
            VALUES (?, 0, 0, 0, 0, ?)
            ON CONFLICT(anchor_id) DO NOTHING
        """, (anchor_id, fields["ts_ms"]))

        for col, val in fields.items():
            conn.execute(
                f"UPDATE door_state SET {col} = ? WHERE anchor_id = ?",
                (val, anchor_id)
            )
        conn.commit()
        conn.close()


def mark_mqtt_sent(event_id: int):
    with _lock:
        conn = get_conn()
        conn.execute("UPDATE events SET mqtt_sent = 1 WHERE id = ?", (event_id,))
        conn.commit()
        conn.close()


def get_unsent_events(limit: int = 50) -> list:
    with _lock:
        conn = get_conn()
        rows = conn.execute(
            "SELECT * FROM events WHERE mqtt_sent = 0 ORDER BY id ASC LIMIT ?",
            (limit,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]


def get_recent_events(limit: int = 100) -> list:
    with _lock:
        conn = get_conn()
        rows = conn.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]


def get_all_tags() -> list:
    with _lock:
        conn = get_conn()
        rows = conn.execute("SELECT * FROM tag_state ORDER BY last_seen_ms DESC").fetchall()
        conn.close()
        return [dict(r) for r in rows]


def get_all_anchors() -> list:
    with _lock:
        conn = get_conn()
        rows = conn.execute("""
            SELECT a.*,
                   d.locked, d.fire, d.rex, d.ajar,
                   c.rex_duration_ms, c.relay_hold_ms,
                   c.door_ajar_timeout_ms, c.signal_loss_timeout_ms,
                   c.signal_loss_mode, c.buzzer_enable, c.buzzer_duration_ms,
                   c.tz, c.wifi_count, c.config_status, c.updated_ms AS config_updated_ms
            FROM anchors a
            LEFT JOIN door_state   d ON a.anchor_id = d.anchor_id
            LEFT JOIN anchor_config c ON a.anchor_id = c.anchor_id
            ORDER BY a.anchor_id
        """).fetchall()
        conn.close()
        return [dict(r) for r in rows]


# ── Config parameter bounds ────────────────────────────────────────────
# WIFI_MAX_NETWORKS must match WIFI_MAX_NETWORKS in anchor firmware (wifi_manager.h)
WIFI_MAX_NETWORKS = 3

import re as _re
_TZ_RE = _re.compile(r"^[+-](?:1[0-4]|\d):[0-5]\d$")

# Each entry uses one validation strategy:
#   "min"/"max"   — numeric range, clamped to int
#   "values"      — exact whitelist
#   "pattern"     — compiled regex (string fields)
#   "wifi_list"   — list of {ssid, password} dicts (special handling)
CONFIG_SCHEMA = {
    "rex_duration_ms":        {"default": 3000,   "min": 500,    "max": 30000},
    "relay_hold_ms":          {"default": 500,    "min": 100,    "max": 5000},
    "door_ajar_timeout_ms":   {"default": 30000,  "min": 5000,   "max": 300000},
    "signal_loss_timeout_ms": {"default": 60000,  "min": 10000,  "max": 600000},
    "signal_loss_mode":       {"default": "LOCK",  "values":     ["LOCK", "UNLOCK"]},
    "buzzer_enable":          {"default": 1,       "values":     [0, 1]},
    "buzzer_duration_ms":     {"default": 1000,   "min": 100,    "max": 10000},
    # UTC offset string accepted by the anchor's parse_tz_string()
    # Format: "[+-]H:MM" or "[+-]HH:MM", range ±14:00 (±50400 s)
    "tz":                     {"default": "+0:00", "pattern": _TZ_RE},
    # Up to WIFI_MAX_NETWORKS {ssid, password} entries; SSID ≤32, password ≤64 chars
    "wifi_networks":          {"default": [],      "type": "wifi_list"},
}


def _clamp_config(params: dict) -> dict:
    """Validate and clamp config values against schema.

    For wifi_networks: returns the list as a Python object; also injects
    wifi_count so both columns stay in sync.
    """
    out = {}
    for key, val in params.items():
        if key not in CONFIG_SCHEMA:
            continue
        schema = CONFIG_SCHEMA[key]
        if "values" in schema:
            if val in schema["values"]:
                out[key] = val
        elif "min" in schema and "max" in schema:
            out[key] = max(schema["min"], min(schema["max"], int(val)))
        elif "pattern" in schema:
            if isinstance(val, str) and schema["pattern"].match(val):
                out[key] = val
        elif schema.get("type") == "wifi_list":
            if not isinstance(val, list):
                import logging as _log
                _log.getLogger("database").warning(
                    "wifi_networks is not a list (type=%s) — skipped", type(val).__name__)
                continue
            nets = []
            for i, entry in enumerate(val[:WIFI_MAX_NETWORKS]):
                if not isinstance(entry, dict):
                    import logging as _log
                    _log.getLogger("database").warning(
                        "wifi_networks[%d] is not a dict — skipped", i)
                    continue
                ssid = entry.get("ssid", "")
                pwd  = entry.get("password", "")
                if isinstance(ssid, str) and 1 <= len(ssid) <= 32 \
                        and isinstance(pwd, str) and len(pwd) <= 64:
                    nets.append({"ssid": ssid, "password": pwd})
                else:
                    import logging as _log
                    _log.getLogger("database").warning(
                        "wifi_networks[%d] ssid=%r (%d chars) pwd=*** (%d chars) — "
                        "failed validation (ssid 1-32, pwd 0-64)",
                        i, ssid, len(ssid) if isinstance(ssid, str) else -1,
                        len(pwd) if isinstance(pwd, str) else -1)
            out["wifi_networks"] = nets
            out["wifi_count"]    = len(nets)   # keep cached count in sync
    return out


def _decode_config_row(row) -> dict:
    """Convert a raw anchor_config DB row to a Python dict.

    Deserialises wifi_networks from JSON text to a list and ensures
    wifi_count matches the list length.
    """
    d = dict(row)
    try:
        d["wifi_networks"] = json.loads(d.get("wifi_networks") or "[]")
    except (json.JSONDecodeError, TypeError):
        d["wifi_networks"] = []
    d["wifi_count"] = len(d["wifi_networks"])
    return d


def get_anchor_config(anchor_id: int) -> dict:
    """Return config for anchor, inserting defaults if not present."""
    with _lock:
        conn = get_conn()
        row = conn.execute(
            "SELECT * FROM anchor_config WHERE anchor_id = ?", (anchor_id,)
        ).fetchone()
        if not row:
            conn.execute(
                "INSERT OR IGNORE INTO anchor_config (anchor_id, updated_ms) VALUES (?, ?)",
                (anchor_id, int(time.time() * 1000))
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM anchor_config WHERE anchor_id = ?", (anchor_id,)
            ).fetchone()
        conn.close()
        return _decode_config_row(row)


def upsert_anchor_config(anchor_id: int, params: dict) -> dict:
    """Update config fields (validated+clamped). Returns the saved config."""
    safe = _clamp_config(params)
    if not safe:
        return get_anchor_config(anchor_id)
    with _lock:
        conn = get_conn()
        conn.execute(
            "INSERT OR IGNORE INTO anchor_config (anchor_id, updated_ms) VALUES (?, ?)",
            (anchor_id, int(time.time() * 1000))
        )
        for col, val in safe.items():
            # wifi_networks is a Python list — serialise to JSON for SQLite storage
            db_val = json.dumps(val) if isinstance(val, list) else val
            conn.execute(
                f"UPDATE anchor_config SET {col} = ? WHERE anchor_id = ?",
                (db_val, anchor_id)
            )
        conn.execute(
            "UPDATE anchor_config SET config_status = 'PENDING', updated_ms = ? WHERE anchor_id = ?",
            (int(time.time() * 1000), anchor_id)
        )
        conn.commit()
        conn.close()
    return get_anchor_config(anchor_id)


def mark_config_applied(anchor_id: int):
    with _lock:
        conn = get_conn()
        conn.execute(
            "UPDATE anchor_config SET config_status = 'APPLIED' WHERE anchor_id = ?",
            (anchor_id,)
        )
        conn.commit()
        conn.close()


def mark_config_failed(anchor_id: int):
    with _lock:
        conn = get_conn()
        conn.execute(
            "UPDATE anchor_config SET config_status = 'FAILED' WHERE anchor_id = ?",
            (anchor_id,)
        )
        conn.commit()
        conn.close()


def get_pending_configs() -> list:
    with _lock:
        conn = get_conn()
        rows = conn.execute(
            "SELECT * FROM anchor_config WHERE config_status = 'PENDING'"
        ).fetchall()
        conn.close()
        return [_decode_config_row(r) for r in rows]


# ── Anchor certificate ledger (mTLS revocation) ───────────────────────

def register_anchor_cert(anchor_id: int, serial_hex: str):
    """Record a newly issued anchor cert serial in the ledger."""
    with _lock:
        conn = get_conn()
        conn.execute("""
            INSERT OR REPLACE INTO anchor_certs (serial_hex, anchor_id, issued_ms, revoked)
            VALUES (?, ?, ?, 0)
        """, (serial_hex.upper(), anchor_id, int(time.time() * 1000)))
        conn.commit()
        conn.close()


def is_cert_revoked(serial_hex: str) -> bool:
    """Return True if the cert serial is unknown (never registered) or revoked."""
    with _lock:
        conn = get_conn()
        row = conn.execute(
            "SELECT revoked FROM anchor_certs WHERE serial_hex = ?",
            (serial_hex.upper(),)
        ).fetchone()
        conn.close()
    if row is None:
        return True   # unknown cert — reject
    return bool(row["revoked"])


def revoke_anchor_cert(serial_hex: str):
    """Mark a cert serial as revoked. The anchor will be refused on next connect."""
    with _lock:
        conn = get_conn()
        conn.execute(
            "UPDATE anchor_certs SET revoked = 1 WHERE serial_hex = ?",
            (serial_hex.upper(),)
        )
        conn.commit()
        conn.close()


def next_available_anchor_id() -> int:
    """Return the lowest unused positive anchor_id.

    Queries anchor_certs (not anchors) so that IDs claimed during the current
    bootstrap session are visible immediately — before the anchor's first
    heartbeat inserts a row into anchors.  Safe under asyncio's single-threaded
    model because generate_anchor_cert() inserts into anchor_certs synchronously
    before returning, with no await between the query and the insert.

    After a factory reset deregister_anchor() deletes the cert rows, so the
    freed ID will appear as a gap and be reused by the next device.
    """
    with _lock:
        conn = get_conn()
        rows = conn.execute(
            "SELECT DISTINCT anchor_id FROM anchor_certs WHERE anchor_id > 0"
        ).fetchall()
        conn.close()
    used = {row[0] for row in rows}
    n = 1
    while n in used:
        n += 1
    return n


def deregister_anchor(anchor_id: int):
    """Delete all records for an anchor after a factory reset.

    Called when a FACTORY_RESET message is received.  The anchor erases its
    NVS and reboots with CN=0 (bootstrap cert), which triggers zero-touch
    re-provisioning.  Deleting the cert rows (not just revoking them) makes
    the anchor_id immediately available to next_available_anchor_id() so the
    next provisioned device can reuse it.

    Events are kept as an audit trail — they reference anchor_id but are
    never deleted.
    """
    with _lock:
        conn = get_conn()
        conn.execute("DELETE FROM anchor_certs  WHERE anchor_id = ?", (anchor_id,))
        conn.execute("DELETE FROM anchors        WHERE anchor_id = ?", (anchor_id,))
        conn.execute("DELETE FROM door_state     WHERE anchor_id = ?", (anchor_id,))
        conn.execute("DELETE FROM anchor_config  WHERE anchor_id = ?", (anchor_id,))
        conn.commit()
        conn.close()


def revoke_other_anchor_certs(anchor_id: int, keep_serial: str):
    """Revoke all certs for anchor_id except keep_serial (the newly issued one).

    Called after a successful REPROVISION_ACK to invalidate any previous certs
    the anchor may have used, preventing replay with stolen old credentials.
    """
    with _lock:
        conn = get_conn()
        conn.execute(
            "UPDATE anchor_certs SET revoked = 1 "
            "WHERE anchor_id = ? AND serial_hex != ? AND revoked = 0",
            (anchor_id, keep_serial.upper())
        )
        conn.commit()
        conn.close()


# ── Firmware file registry ────────────────────────────────────────────

def insert_firmware(filename: str, version: str, size_bytes: int, sha256: str) -> int:
    with _lock:
        conn = get_conn()
        c = conn.cursor()
        c.execute(
            "INSERT INTO firmware_files (filename, version, size_bytes, sha256, uploaded_ms) "
            "VALUES (?, ?, ?, ?, ?)",
            (filename, version, size_bytes, sha256, int(time.time() * 1000))
        )
        fw_id = c.lastrowid
        conn.commit()
        conn.close()
        return fw_id


def get_firmware_files() -> list:
    with _lock:
        conn = get_conn()
        rows = conn.execute(
            "SELECT * FROM firmware_files ORDER BY uploaded_ms DESC"
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]


def get_firmware_by_id(fw_id: int) -> dict | None:
    with _lock:
        conn = get_conn()
        row = conn.execute(
            "SELECT * FROM firmware_files WHERE id = ?", (fw_id,)
        ).fetchone()
        conn.close()
        return dict(row) if row else None


def delete_firmware_record(fw_id: int):
    with _lock:
        conn = get_conn()
        conn.execute("DELETE FROM firmware_files WHERE id = ?", (fw_id,))
        conn.commit()
        conn.close()


# ── OTA status tracking ───────────────────────────────────────────────

def set_anchor_ota_status(anchor_id: int, status: str, percent: int = 0):
    with _lock:
        conn = get_conn()
        conn.execute(
            "UPDATE anchors SET ota_status = ?, ota_percent = ? WHERE anchor_id = ?",
            (status, percent, anchor_id)
        )
        conn.commit()
        conn.close()


def get_anchor_ota_status(anchor_id: int) -> str:
    with _lock:
        conn = get_conn()
        row = conn.execute(
            "SELECT ota_status FROM anchors WHERE anchor_id = ?", (anchor_id,)
        ).fetchone()
        conn.close()
        return row["ota_status"] if row else "IDLE"


def set_anchor_fw_version(anchor_id: int, version: str):
    with _lock:
        conn = get_conn()
        conn.execute(
            "UPDATE anchors SET fw_version = ? WHERE anchor_id = ?",
            (version, anchor_id)
        )
        conn.commit()
        conn.close()


def get_alerts(limit: int = 50) -> list:
    """Return recent high-priority events (fire, forced entry, tag lost)."""
    alert_types = ("EVT_FIRE_ALARM", "EVT_ALARM_DOOR_FORCED",
                   "EVT_ALARM_UNAUTHORIZED", "EVT_TAG_LOST")
    placeholders = ",".join("?" * len(alert_types))
    with _lock:
        conn = get_conn()
        rows = conn.execute(
            f"SELECT * FROM events WHERE type IN ({placeholders}) "
            f"ORDER BY id DESC LIMIT ?",
            (*alert_types, limit)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
