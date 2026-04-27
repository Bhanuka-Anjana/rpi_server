# tcp_server.py — mTLS TCP socket server (Anchor → RPi)
#
# Each anchor opens a persistent mTLS connection to RPi:5005.
# Messages are newline-delimited JSON, one event per line.
#
# Security:
#   - Server presents server.crt (signed by the WMS CA).
#   - Anchor presents its unique anchor.crt (also signed by the WMS CA).
#   - Server verifies anchor cert → CA, then checks the serial number against
#     the anchor_certs ledger in the DB (rejects unknown/revoked certs).
#   - anchor_id is extracted from the cert CN (not trusted from JSON payload).
#
# PKI setup (one-time):   python3 pki/generate_ca.py
# Provision new anchor:   python3 pki/provision_anchor.py --id <N>

import asyncio
import json
import logging
import ssl
import threading
import time

import database as db
import pki_utils
from config import CA_CERT_PATH, PKI_DIR, SERVER_CERT_PATH, SERVER_KEY_PATH, TCP_HOST, TCP_PORT

log = logging.getLogger("tcp_server")

# Shared asyncio queue — tcp_server puts events here, mqtt_publisher reads them
event_queue: asyncio.Queue = None

# Running event loop — set by run_tcp_server
_loop: asyncio.AbstractEventLoop | None = None

# Broadcast callback — set by main.py via set_broadcast_fn()
# Called on the asyncio loop to push events to all SSE clients.
_broadcast_fn = None

# Active anchor writers — keyed by anchor_id for config push
_anchor_writers: dict[int, asyncio.StreamWriter] = {}

# Pending reprovision tracking — anchor_id → new_serial_hex
_pending_reprovisions: dict[int, str] = {}

# Pending OTA tracking — anchor_id → firmware_file_id
_pending_ota: dict[int, int] = {}

# High-frequency event types:
#   - Not written to events history table (would create massive write storm)
#   - DB persist is fire-and-forget (don't block the asyncio loop waiting for it)
_HIGH_FREQ_TYPES = frozenset({"EVT_RTLS_UPDATE", "EVT_HEARTBEAT"})

# Rate-limit tag_state DB writes — SSE delivers real-time position, DB only needs
# a fresh snapshot for page reloads. Write at most once per _TAG_DB_INTERVAL seconds.
_tag_db_lock    = threading.Lock()
_tag_last_write: dict[int, float] = {}
_TAG_DB_INTERVAL = 0.25   # seconds — 4 writes/sec per tag maximum


def set_broadcast_fn(fn):
    """Called by main.py to register the SSE broadcast callback."""
    global _broadcast_fn
    _broadcast_fn = fn


def _normalize_rtls_update(evt: dict):
    """Map Ethernet RTLS payload shape to legacy top-level fields.

    Incoming shape:
      {"type": "EVT_RTLS_UPDATE", "payload": {"TWR": {"a16": "E34A", "D": 91, "X": 0}}}

    Produces top-level tag_uid (int), dist_cm (int), escort (0/1).
    """
    if evt.get("type") != "EVT_RTLS_UPDATE":
        return

    payload = evt.get("payload")
    if not isinstance(payload, dict):
        return

    twr = payload.get("TWR")
    if isinstance(twr, list):
        twr = twr[0] if twr else None
    if not isinstance(twr, dict):
        return

    if evt.get("tag_uid") is None:
        a16 = twr.get("a16")
        if a16 is not None:
            try:
                evt["tag_uid"] = int(str(a16).strip(), 16)
            except (TypeError, ValueError):
                pass

    if evt.get("dist_cm") is None:
        d = twr.get("D")
        if d is not None:
            try:
                evt["dist_cm"] = int(d)
            except (TypeError, ValueError):
                pass

    if evt.get("escort") is None:
        x = twr.get("X")
        if x is not None:
            try:
                evt["escort"] = 1 if int(x) else 0
            except (TypeError, ValueError):
                pass


def _build_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(SERVER_CERT_PATH, SERVER_KEY_PATH)
    ctx.load_verify_locations(CA_CERT_PATH)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def _extract_anchor_id(writer: asyncio.StreamWriter) -> tuple[int | None, str]:
    ssl_obj = writer.get_extra_info("ssl_object")
    if ssl_obj is None:
        return None, ""

    cert = ssl_obj.getpeercert()
    if not cert:
        return None, ""

    subject = dict(x[0] for x in cert.get("subject", ()))
    cn = subject.get("commonName", "")
    try:
        anchor_id = int(cn)
    except ValueError:
        log.warning("[TLS] Rejected peer: CN '%s' is not a numeric anchor ID", cn)
        return None, ""

    serial_raw = cert.get("serialNumber", "0")
    try:
        serial_hex = f"{int(serial_raw, 16):040X}"
    except ValueError:
        serial_hex = f"{int(serial_raw):040X}"

    return anchor_id, serial_hex


async def push_config(anchor_id: int, cfg: dict):
    """Send a CONFIG message down to a connected anchor. No-op if offline."""
    writer = _anchor_writers.get(anchor_id)
    if not writer:
        log.info("[TCP] Config push deferred — anchor %d not connected", anchor_id)
        return
    _SKIP = {"anchor_id", "config_status", "updated_ms", "wifi_count"}
    payload = {k: v for k, v in cfg.items() if k not in _SKIP}
    payload["type"] = "CONFIG"
    payload["anchor_id"] = anchor_id
    try:
        nets = payload.get("wifi_networks", [])
        if isinstance(nets, str):
            try:
                payload["wifi_networks"] = json.loads(nets)
                nets = payload["wifi_networks"]
            except (json.JSONDecodeError, TypeError):
                payload["wifi_networks"] = []
                nets = []
        raw = json.dumps(payload) + "\n"
        writer.write(raw.encode())
        await writer.drain()
        ssids = [n["ssid"] for n in nets if isinstance(n, dict)] if isinstance(nets, list) else []
        log.info("[TCP] Config pushed to anchor %d — wifi_networks=%d %s",
                 anchor_id, len(ssids), ssids)
    except Exception as e:
        log.warning("[TCP] Config push failed for anchor %d: %s", anchor_id, e)


async def kick_anchor(anchor_id: int):
    """Close the TCP connection for anchor_id."""
    writer = _anchor_writers.pop(anchor_id, None)
    if writer:
        writer.close()
        log.info("[TCP] Kicked anchor %d (manually removed)", anchor_id)


async def push_command(anchor_id: int, cmd: dict):
    """Send a downlink command to a connected anchor."""
    writer = _anchor_writers.get(anchor_id)
    if not writer:
        log.warning("[TCP] Command push failed — anchor %d not connected", anchor_id)
        return
    try:
        writer.write((json.dumps(cmd) + "\n").encode())
        await writer.drain()
        log.info("[TCP] Command %s pushed to anchor %d", cmd.get("type"), anchor_id)
    except Exception as e:
        log.warning("[TCP] Command push failed for anchor %d: %s", anchor_id, e)


def _persist_event(evt: dict):
    """Executor thread: all SQLite writes for one event.

    For CONFIG_ACK returns the _config_update dict that the caller should
    broadcast; for all other events returns None.
    """
    anchor_id = evt.get("anchor_id", 0)
    etype     = evt.get("type", "UNKNOWN")

    # ── FACTORY_RESET ─────────────────────────────────────────────────────
    if etype == "FACTORY_RESET":
        log.warning("[TCP] Anchor %d factory reset — revoking all certs", anchor_id)
        db.deregister_anchor(anchor_id)
        _anchor_writers.pop(anchor_id, None)
        db.insert_event(evt)
        return None

    # ── CONFIG_ACK ────────────────────────────────────────────────────────
    if etype == "CONFIG_ACK":
        status = evt.get("status", "")
        if status == "ok":
            db.mark_config_applied(anchor_id)
            log.info("[TCP] Config ACK from anchor %d — APPLIED", anchor_id)
        else:
            db.mark_config_failed(anchor_id)
            log.warning("[TCP] Config ACK from anchor %d — FAILED", anchor_id)
        cfg = db.get_anchor_config(anchor_id)
        cfg["type"]      = "_config_update"
        cfg["anchor_id"] = anchor_id
        cfg["ts_ms"]     = evt.get("ts_ms", int(time.time() * 1000))
        return cfg  # caller broadcasts this

    # ── High-frequency types — skip history insert, skip anchor heartbeat ──
    if etype in _HIGH_FREQ_TYPES:
        # For RTLS: rate-limited tag_state write so the snapshot stays fresh
        if etype == "EVT_RTLS_UPDATE":
            tag_uid = evt.get("tag_uid")
            if tag_uid is not None:
                now = time.time()
                with _tag_db_lock:
                    if now - _tag_last_write.get(tag_uid, 0) >= _TAG_DB_INTERVAL:
                        _tag_last_write[tag_uid] = now
                        should_write = True
                    else:
                        should_write = False
                if should_write:
                    db.upsert_tag_state(tag_uid, anchor_id, evt.get("dist_cm"),
                                        gear=evt.get("gear"), escort=evt.get("escort", 0))
        elif etype == "EVT_HEARTBEAT":
            db.upsert_anchor(anchor_id)
        return None

    # ── All other events — full persistence ───────────────────────────────
    db.upsert_anchor(anchor_id)
    row_id = db.insert_event(evt)
    evt["_db_id"] = row_id

    if etype in ("EVT_DOOR_LOCKED", "EVT_DOOR_UNLOCKED"):
        db.upsert_door_state(anchor_id,
                             locked=1 if etype == "EVT_DOOR_LOCKED" else 0)

    elif etype == "EVT_FIRE_ALARM":
        db.upsert_door_state(anchor_id, fire=1)

    elif etype == "EVT_FIRE_CLEARED":
        db.upsert_door_state(anchor_id, fire=0)

    elif etype == "EVT_REX_PRESSED":
        db.upsert_door_state(anchor_id, rex=1)

    elif etype == "EVT_BOOT":
        boot_count = evt.get("boot_count")
        db.upsert_anchor(anchor_id, boot_count=boot_count)
        log.info("[TCP] anchor=%d BOOT boot_count=%s", anchor_id, boot_count)
        if evt.get("fw_version"):
            db.set_anchor_fw_version(anchor_id, evt["fw_version"])
        ota_st = db.get_anchor_ota_status(anchor_id)
        if ota_st in ("IN_PROGRESS", "COMPLETE"):
            db.set_anchor_ota_status(anchor_id, "COMPLETE", 100)
            _pending_ota.pop(anchor_id, None)

    elif etype == "OTA_PROGRESS":
        db.set_anchor_ota_status(anchor_id, "IN_PROGRESS", evt.get("percent", 0))
        log.info("[TCP] anchor=%d OTA_PROGRESS %d%%", anchor_id, evt.get("percent", 0))

    elif etype == "OTA_COMPLETE":
        db.set_anchor_ota_status(anchor_id, "COMPLETE", 100)
        if evt.get("fw_version"):
            db.set_anchor_fw_version(anchor_id, evt["fw_version"])
        _pending_ota.pop(anchor_id, None)
        log.info("[TCP] anchor=%d OTA_COMPLETE fw=%s", anchor_id, evt.get("fw_version"))

    elif etype == "OTA_FAILED":
        db.set_anchor_ota_status(anchor_id, "FAILED", 0)
        _pending_ota.pop(anchor_id, None)
        log.warning("[TCP] anchor=%d OTA_FAILED reason=%s", anchor_id, evt.get("reason"))

    elif etype in ("EVT_TAG_APPROACH", "EVT_TAG_AT_DOOR", "EVT_TAG_RETREAT"):
        tag_uid = evt.get("tag_uid")
        if tag_uid is not None:
            db.upsert_tag_state(tag_uid, anchor_id, evt.get("dist_cm"),
                                gear=evt.get("gear"), escort=evt.get("escort", 0))

    elif etype == "EVT_DOOR_LOCKED":
        tag_uid = evt.get("tag_uid")
        if tag_uid is not None:
            db.upsert_tag_state(tag_uid, anchor_id, evt.get("dist_cm"), escort=0)

    elif etype == "EVT_ESCORT_ACTIVE":
        tag_uid = evt.get("tag_uid")
        if tag_uid is not None:
            db.upsert_tag_state(tag_uid, anchor_id, evt.get("dist_cm"), escort=1)

    elif etype == "EVT_TAG_LOST":
        tag_uid = evt.get("tag_uid")
        if tag_uid is not None:
            db.upsert_tag_state(tag_uid, anchor_id, None, escort=0)

    return None


async def _handle_anchor(reader: asyncio.StreamReader,
                          writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")

    anchor_id_cert, serial_hex = _extract_anchor_id(writer)
    if anchor_id_cert is None:
        log.warning("[TLS] Dropping connection from %s — bad cert CN", peer)
        writer.close()
        return

    if db.is_cert_revoked(serial_hex):
        log.warning("[TLS] Dropping anchor %d (%s) — cert serial %s is revoked/unknown",
                    anchor_id_cert, peer, serial_hex)
        writer.close()
        return

    # ── Zero-touch bootstrap ───────────────────────────────────────────────
    if anchor_id_cert == 0:
        new_id = db.next_available_anchor_id()
        log.info("[TCP] Bootstrap anchor from %s — assigning anchor_id=%d", peer, new_id)
        try:
            cert = pki_utils.generate_anchor_cert(new_id, PKI_DIR)
        except Exception as e:
            log.error("[TCP] Bootstrap cert generation failed: %s", e)
            writer.close()
            return
        _anchor_writers[new_id] = writer
        _pending_reprovisions[new_id] = cert["serial_hex"]
        await push_command(new_id, {
            "type":        "REPROVISION",
            "anchor_id":   new_id,
            "ca_cert":     cert["ca_cert_pem"],
            "client_cert": cert["client_cert_pem"],
            "client_key":  cert["client_key_pem"],
        })
        anchor_id_cert = new_id

    log.info("[TCP] Anchor %d connected from %s (cert serial …%s)",
             anchor_id_cert, peer, serial_hex[-8:])

    _anchor_writers[anchor_id_cert] = writer

    cfg = db.get_anchor_config(anchor_id_cert)
    if cfg.get("config_status") == "PENDING":
        await push_config(anchor_id_cert, cfg)

    loop   = asyncio.get_running_loop()
    buffer = b""
    try:
        while True:
            chunk = await reader.read(4096)   # larger read buffer reduces syscall overhead
            if not chunk:
                break

            buffer += chunk
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    evt   = json.loads(line.decode("utf-8"))
                    etype = evt.get("type", "")
                    evt["ts_ms"]    = int(time.time() * 1000)
                    evt["anchor_id"] = anchor_id_cert

                    # ── Inline control messages (no broadcast) ─────────────
                    if etype == "TIME_SYNC_REQ":
                        reply = json.dumps({"type": "TIME_SYNC",
                                            "epoch": int(time.time())}) + "\n"
                        writer.write(reply.encode())
                        await writer.drain()
                        log.info("[TCP] TIME_SYNC sent to anchor %d", anchor_id_cert)
                        continue

                    if etype == "REPROVISION_ACK":
                        status     = evt.get("status", "")
                        new_serial = _pending_reprovisions.pop(anchor_id_cert, None)
                        if status == "ok" and new_serial:
                            await loop.run_in_executor(
                                None, db.revoke_other_anchor_certs,
                                anchor_id_cert, new_serial
                            )
                            log.info("[TCP] Anchor %d reprovisioned — old certs revoked",
                                     anchor_id_cert)
                        else:
                            log.warning("[TCP] REPROVISION_ACK from anchor %d: status=%s",
                                        anchor_id_cert, status)
                        continue

                    # ── Normalize RTLS payload (fast, on loop) ─────────────
                    _normalize_rtls_update(evt)

                    # ── CONFIG_ACK — DB first, then broadcast result ────────
                    if etype == "CONFIG_ACK":
                        cfg_update = await loop.run_in_executor(None, _persist_event, evt)
                        if cfg_update is not None:
                            if _broadcast_fn:
                                _broadcast_fn(cfg_update)
                            if event_queue is not None:
                                try:
                                    event_queue.put_nowait(cfg_update)
                                except asyncio.QueueFull:
                                    pass
                        continue

                    # ── All other events — BROADCAST FIRST ─────────────────
                    # Deliver to SSE clients immediately, before any DB work.
                    if _broadcast_fn:
                        _broadcast_fn(evt)

                    if event_queue is not None:
                        try:
                            event_queue.put_nowait(evt)
                        except asyncio.QueueFull:
                            pass

                    log.debug("[TCP] anchor=%d  type=%s  tag=%s  dist=%s cm",
                              anchor_id_cert, etype,
                              evt.get("tag_uid", "-"), evt.get("dist_cm", "-"))

                    # ── DB persistence ─────────────────────────────────────
                    if etype in _HIGH_FREQ_TYPES:
                        # Fire-and-forget — don't block the asyncio loop
                        loop.run_in_executor(None, _persist_event, evt.copy())
                    else:
                        # Await for state-changing events so subsequent reads see fresh data
                        await loop.run_in_executor(None, _persist_event, evt)

                    # Re-push config after boot (OTA / power cycle / reconnect)
                    if etype == "EVT_BOOT":
                        cfg = db.get_anchor_config(anchor_id_cert)
                        await push_config(anchor_id_cert, cfg)

                except json.JSONDecodeError as e:
                    log.warning("[TCP] Bad JSON from anchor %d: %s — raw: %s",
                                anchor_id_cert, e, line[:120])

    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    finally:
        log.info("[TCP] Anchor %d disconnected from %s", anchor_id_cert, peer)
        if _anchor_writers.get(anchor_id_cert) is writer:
            del _anchor_writers[anchor_id_cert]
        writer.close()


async def run_tcp_server(queue: asyncio.Queue):
    global event_queue, _loop
    event_queue = queue
    _loop = asyncio.get_running_loop()

    ssl_ctx = _build_ssl_context()
    server  = await asyncio.start_server(
        _handle_anchor, TCP_HOST, TCP_PORT, ssl=ssl_ctx
    )
    addr = server.sockets[0].getsockname()
    log.info("[TCP] mTLS server listening on %s:%s", addr[0], addr[1])

    async with server:
        await server.serve_forever()
