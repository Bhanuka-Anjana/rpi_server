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
import math
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
_HIGH_FREQ_TYPES = frozenset({"EVT_RTLS_UPDATE", "EVT_TWR_SAMPLE", "EVT_HEARTBEAT"})

_LOCK_STATE_HOLD_MS = 5000
_LOCK_STATE_RENEW_MS = 2000
_TWR_TAG_STALE_MS = 5000
_DEFAULT_LOCK_DISTANCE_CM = 300
_anchor_lock_distance_cm: dict[int, int] = {}
_anchor_lock_decision: dict[int, bool] = {}
_anchor_lock_last_sent_ms: dict[int, int] = {}
_anchor_twr_tags: dict[int, dict[int, dict]] = {}
_anchor_twr_expiry_tasks: dict[int, asyncio.Task] = {}

_RAW_TWR_START = 0xAA
_RAW_TWR_END = 0x55
_RAW_TWR_FRAME_LEN = 15

# Rate-limit tag_state DB writes — SSE delivers real-time position, DB only needs
# a fresh snapshot for page reloads. Write at most once per _TAG_DB_INTERVAL seconds.
_tag_db_lock    = threading.Lock()
_tag_last_write: dict[int, float] = {}
_TAG_DB_INTERVAL = 0.25   # seconds — 4 writes/sec per tag maximum


def _parse_eui64(value, *, hex_if_16: bool = False) -> int | None:
    """Parse an EUI-64 from int, decimal string, or 16-char hex string."""
    if isinstance(value, bool) or value is None:
        return None

    try:
        if isinstance(value, int):
            eui = value
        elif isinstance(value, str):
            raw = value.strip()
            if not raw:
                return None
            raw = raw.removeprefix("0x").removeprefix("0X")
            raw = raw.replace(":", "").replace("-", "").replace(" ", "")
            if not raw:
                return None
            is_hex = (hex_if_16 and len(raw) == 16) or any(
                c in "ABCDEFabcdef" for c in raw
            )
            base = 16 if is_hex else 10
            eui = int(raw, base)
        else:
            return None
    except (TypeError, ValueError):
        return None

    if 0 < eui <= 0xFFFFFFFFFFFFFFFF:
        return eui
    return None


def _extract_hello_eui(evt: dict) -> int | None:
    payload = evt.get("payload")
    if payload is not None and not isinstance(payload, dict):
        eui = _parse_eui64(payload, hex_if_16=True)
        if eui is not None:
            return eui

    sources = [payload, evt] if isinstance(payload, dict) else [evt]

    for src in sources:
        for key in ("eui", "eui64", "eui_id", "anchor_eui", "anchor_id", "id"):
            if key in src:
                eui = _parse_eui64(
                    src.get(key),
                    hex_if_16=key in ("eui", "eui64", "anchor_eui"),
                )
                if eui is not None:
                    return eui
    return None


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


def _decode_raw_twr_frame(frame: bytes) -> dict | None:
    """Decode the raw 15-byte UART TWR frame on the server side."""
    if len(frame) != _RAW_TWR_FRAME_LEN:
        return None
    if frame[0] != _RAW_TWR_START or frame[14] != _RAW_TWR_END:
        return None

    checksum = 0
    for b in frame[1:13]:
        checksum ^= b
    if checksum != frame[13]:
        log.warning("[TCP] Dropped raw TWR frame: checksum calc=0x%02X rx=0x%02X",
                    checksum, frame[13])
        return None

    tag_uid = frame[1] | (frame[2] << 8)
    anchor_short_id = frame[3] | (frame[4] << 8)
    dist_cm = frame[5] | (frame[6] << 8)
    range_num = frame[7]
    flags = frame[8]
    x_cm = int.from_bytes(frame[9:11], byteorder="little", signed=True)
    y_cm = int.from_bytes(frame[11:13], byteorder="little", signed=True)

    return {
        "type": "EVT_TWR_SAMPLE",
        "tag_uid": tag_uid,
        "anchor_short_id": anchor_short_id,
        "dist_cm": dist_cm,
        "range_num": range_num,
        "flags": flags,
        "x_cm": x_cm,
        "y_cm": y_cm,
        "checksum": frame[13],
        "escort": 1 if (flags & 0x01) else 0,
        "raw_hex": frame.hex().upper(),
    }


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
    anchor_id = 0 if cn == "0" else _parse_eui64(cn, hex_if_16=True)
    if anchor_id is None:
        log.warning("[TLS] Rejected peer: CN '%s' is not a valid anchor EUI", cn)
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
    _anchor_lock_distance_cm[anchor_id] = int(
        cfg.get("lock_distance_cm") or _DEFAULT_LOCK_DISTANCE_CM
    )
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
    _anchor_lock_decision.pop(anchor_id, None)
    _anchor_lock_last_sent_ms.pop(anchor_id, None)
    _anchor_twr_tags.pop(anchor_id, None)
    task = _anchor_twr_expiry_tasks.pop(anchor_id, None)
    if task:
        task.cancel()
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


async def _push_lock_state(anchor_id: int, locked: bool, evt: dict):
    """Push the server-decided door lock state to the reporting anchor."""
    writer = _anchor_writers.get(anchor_id)
    if not writer:
        return False

    cmd = {
        "type": "LOCK_STATE",
        "anchor_id": anchor_id,
        "locked": bool(locked),
        "hold_ms": _LOCK_STATE_HOLD_MS,
    }
    if evt.get("tag_uid") is not None:
        cmd["tag_uid"] = evt.get("tag_uid")
    if evt.get("dist_cm") is not None:
        cmd["dist_cm"] = evt.get("dist_cm")

    try:
        writer.write((json.dumps(cmd) + "\n").encode())
        await writer.drain()
        log.debug("[TCP] LOCK_STATE locked=%s pushed to anchor %d tag=%s dist=%s",
                  locked, anchor_id, evt.get("tag_uid"), evt.get("dist_cm"))
        return True
    except Exception as e:
        log.warning("[TCP] LOCK_STATE push failed for anchor %d: %s", anchor_id, e)
        return False


def _prune_anchor_twr_tags(anchor_id: int, now_ms: int) -> dict[int, dict]:
    tags = _anchor_twr_tags.get(anchor_id)
    if not tags:
        return {}

    expired = [tag_uid for tag_uid, sample in tags.items()
               if sample.get("expires_at_ms", 0) <= now_ms]
    for tag_uid in expired:
        tags.pop(tag_uid, None)

    if not tags:
        _anchor_twr_tags.pop(anchor_id, None)
        return {}
    return tags


def _anchor_has_in_range_tag(anchor_id: int, threshold: int, now_ms: int) -> bool:
    tags = _prune_anchor_twr_tags(anchor_id, now_ms)
    for sample in tags.values():
        if "in_zone" in sample:
            if sample.get("in_zone"):
                return True
        elif int(sample.get("dist_cm", 65535)) <= threshold:
            return True
    return False


async def _schedule_anchor_twr_expiry(anchor_id: int):
    current_task = asyncio.current_task()
    old_task = _anchor_twr_expiry_tasks.pop(anchor_id, None)
    if old_task and old_task is not current_task:
        old_task.cancel()

    tags = _anchor_twr_tags.get(anchor_id)
    if not tags:
        return

    next_expiry_ms = min(sample["expires_at_ms"] for sample in tags.values())
    _anchor_twr_expiry_tasks[anchor_id] = asyncio.create_task(
        _anchor_twr_expiry_worker(anchor_id, next_expiry_ms)
    )


async def _anchor_twr_expiry_worker(anchor_id: int, expiry_ms: int):
    try:
        delay_s = max(0.0, (expiry_ms - int(time.time() * 1000)) / 1000.0)
        await asyncio.sleep(delay_s)

        now_ms = int(time.time() * 1000)
        threshold = _anchor_lock_distance_cm.get(anchor_id)
        if threshold is None:
            cfg = db.get_anchor_config(anchor_id)
            threshold = int(cfg.get("lock_distance_cm") or _DEFAULT_LOCK_DISTANCE_CM)
            _anchor_lock_distance_cm[anchor_id] = threshold

        locked = _anchor_has_in_range_tag(anchor_id, threshold, now_ms)
        if not locked and _anchor_lock_decision.get(anchor_id) is True:
            _anchor_lock_decision[anchor_id] = False
            evt = {
                "type": "LOCK_STATE_TIMEOUT",
                "ts_ms": now_ms,
                "anchor_id": anchor_id,
                "anchor_id_str": str(anchor_id),
                "lock_threshold_cm": threshold,
                "lock_window_ms": _LOCK_STATE_HOLD_MS,
                "lock_decision": "UNLOCK",
                "lock_decision_changed": True,
                "lock_command_sent": False,
                "lock_expiry_owner": "anchor",
            }
            if _broadcast_fn:
                _broadcast_fn(evt)

        await _schedule_anchor_twr_expiry(anchor_id)
    except asyncio.CancelledError:
        pass
    finally:
        if _anchor_twr_expiry_tasks.get(anchor_id) is asyncio.current_task():
            _anchor_twr_expiry_tasks.pop(anchor_id, None)


def _resolve_room_source_anchor(reporting_anchor_id: int, evt: dict) -> dict | None:
    """Return the room anchor used as the x/y coordinate source."""
    anchor_short_id = evt.get("anchor_short_id")
    if anchor_short_id is not None:
        try:
            mapped = db.get_room_anchor_by_uwb_short_id(int(anchor_short_id))
        except (TypeError, ValueError):
            mapped = None
        if mapped is not None:
            return mapped

    return db.get_room_anchor_by_anchor_id(reporting_anchor_id)


def _apply_room_transform(source: dict, evt: dict) -> tuple[int, int] | None:
    x_cm = evt.get("x_cm")
    y_cm = evt.get("y_cm")
    if x_cm is None or y_cm is None:
        return None

    try:
        local_x = float(x_cm)
        local_y = float(y_cm)
        anchor_x = float(source.get("room_x_cm") or 0)
        anchor_y = float(source.get("room_y_cm") or 0)
        theta = math.radians(float(source.get("heading_deg") or 0))
    except (TypeError, ValueError):
        return None

    if source.get("flip_x"):
        local_x = -local_x
    if source.get("flip_y"):
        local_y = -local_y

    cos_t = math.cos(theta)
    sin_t = math.sin(theta)
    global_x = anchor_x + local_x * cos_t - local_y * sin_t
    global_y = anchor_y + local_x * sin_t + local_y * cos_t
    return int(round(global_x)), int(round(global_y))


def _room_lock_targets(source: dict, global_x_cm: int, global_y_cm: int) -> list[dict]:
    targets = []
    for candidate in db.get_room_anchors(int(source["room_id"])):
        if not int(candidate.get("lock_enabled") or 0):
            continue
        radius = int(candidate.get("danger_radius_cm") or 0)
        dx = int(global_x_cm) - int(candidate.get("room_x_cm") or 0)
        dy = int(global_y_cm) - int(candidate.get("room_y_cm") or 0)
        dist_sq = dx * dx + dy * dy
        targets.append({
            **candidate,
            "zone_dist_cm": int(round(math.sqrt(dist_sq))),
            "in_zone": dist_sq <= radius * radius,
        })
    return targets


async def _apply_room_twr_lock_decision(reporting_anchor_id: int, evt: dict) -> bool:
    source = _resolve_room_source_anchor(reporting_anchor_id, evt)
    if source is None:
        return False

    pos = _apply_room_transform(source, evt)
    if pos is None:
        return False

    global_x_cm, global_y_cm = pos
    room_id = int(source["room_id"])
    room_targets = _room_lock_targets(source, global_x_cm, global_y_cm)
    if not room_targets:
        return False

    now_ms = int(time.time() * 1000)
    tag_uid = int(evt["tag_uid"])

    evt["room_id"] = room_id
    evt["room_name"] = source.get("room_name")
    evt["global_x_cm"] = global_x_cm
    evt["global_y_cm"] = global_y_cm
    evt["source_anchor"] = source.get("anchor_id")
    evt["source_anchor_id_str"] = source.get("anchor_id_str")
    evt["source_anchor_eui"] = source.get("eui")
    evt["lock_mode"] = "ROOM_ZONE"
    evt["lock_window_ms"] = _LOCK_STATE_HOLD_MS
    evt["lock_renew_ms"] = _LOCK_STATE_RENEW_MS
    evt["lock_expiry_owner"] = "anchor"
    evt["lock_command_sent"] = False
    evt["lock_targets"] = []

    sent_any = False
    any_locked = False
    changed_any = False

    for target in room_targets:
        target_anchor_id = int(target["anchor_id"])
        locked = bool(target["in_zone"])
        any_locked = any_locked or locked
        previous = _anchor_lock_decision.get(target_anchor_id)
        changed_any = changed_any or (previous is not locked)

        samples = _anchor_twr_tags.setdefault(target_anchor_id, {})
        samples[tag_uid] = {
            "dist_cm": evt.get("dist_cm"),
            "x_cm": evt.get("x_cm"),
            "y_cm": evt.get("y_cm"),
            "global_x_cm": global_x_cm,
            "global_y_cm": global_y_cm,
            "room_id": room_id,
            "zone_dist_cm": target["zone_dist_cm"],
            "danger_radius_cm": target.get("danger_radius_cm"),
            "in_zone": locked,
            "expires_at_ms": now_ms + _TWR_TAG_STALE_MS,
            "range_num": evt.get("range_num"),
            "escort": evt.get("escort", 0),
        }

        await _schedule_anchor_twr_expiry(target_anchor_id)

        target_info = {
            "anchor_id": target_anchor_id,
            "anchor_id_str": str(target_anchor_id),
            "eui": target.get("eui"),
            "room_x_cm": target.get("room_x_cm"),
            "room_y_cm": target.get("room_y_cm"),
            "danger_radius_cm": target.get("danger_radius_cm"),
            "zone_dist_cm": target["zone_dist_cm"],
            "decision": "LOCK" if locked else "UNLOCK",
            "command_sent": False,
        }

        if not locked:
            if previous is True:
                _anchor_lock_decision[target_anchor_id] = False
            evt["lock_targets"].append(target_info)
            continue

        last_sent_ms = _anchor_lock_last_sent_ms.get(target_anchor_id, 0)
        should_send = previous is not True or (now_ms - last_sent_ms) >= _LOCK_STATE_RENEW_MS
        if should_send and await _push_lock_state(target_anchor_id, True, evt):
            _anchor_lock_decision[target_anchor_id] = True
            _anchor_lock_last_sent_ms[target_anchor_id] = now_ms
            sent_any = True
            target_info["command_sent"] = True

        evt["lock_targets"].append(target_info)

    evt["lock_decision"] = "LOCK" if any_locked else "UNLOCK"
    evt["lock_decision_changed"] = changed_any
    evt["lock_command_sent"] = sent_any
    return True


async def _apply_twr_lock_decision(anchor_id: int, evt: dict):
    """Server-owned distance and freshness decision for raw TWR samples."""
    if evt.get("type") != "EVT_TWR_SAMPLE":
        return

    tag_uid = evt.get("tag_uid")
    if tag_uid is None:
        return

    dist_cm = evt.get("dist_cm")
    if dist_cm is None:
        return

    try:
        tag_uid = int(tag_uid)
        dist_cm = int(dist_cm)
    except (TypeError, ValueError):
        return
    evt["tag_uid"] = tag_uid
    evt["dist_cm"] = dist_cm

    if await _apply_room_twr_lock_decision(anchor_id, evt):
        return

    threshold = _anchor_lock_distance_cm.get(anchor_id)
    if threshold is None:
        cfg = db.get_anchor_config(anchor_id)
        threshold = int(cfg.get("lock_distance_cm") or _DEFAULT_LOCK_DISTANCE_CM)
        _anchor_lock_distance_cm[anchor_id] = threshold

    now_ms = int(time.time() * 1000)
    tags = _anchor_twr_tags.setdefault(anchor_id, {})
    tags[tag_uid] = {
        "dist_cm": dist_cm,
        "x_cm": evt.get("x_cm"),
        "y_cm": evt.get("y_cm"),
        "expires_at_ms": now_ms + _TWR_TAG_STALE_MS,
        "range_num": evt.get("range_num"),
        "escort": evt.get("escort", 0),
    }

    locked = _anchor_has_in_range_tag(anchor_id, threshold, now_ms)
    previous = _anchor_lock_decision.get(anchor_id)

    evt["lock_threshold_cm"] = threshold
    evt["lock_mode"] = "DISTANCE_FALLBACK"
    evt["lock_window_ms"] = _LOCK_STATE_HOLD_MS
    evt["lock_renew_ms"] = _LOCK_STATE_RENEW_MS
    evt["lock_expiry_owner"] = "anchor"
    evt["lock_decision"] = "LOCK" if locked else "UNLOCK"
    evt["lock_decision_changed"] = previous is not locked
    evt["lock_command_sent"] = False

    await _schedule_anchor_twr_expiry(anchor_id)

    if not locked:
        if previous is True:
            _anchor_lock_decision[anchor_id] = False
        return

    last_sent_ms = _anchor_lock_last_sent_ms.get(anchor_id, 0)
    should_send = previous is not True or (now_ms - last_sent_ms) >= _LOCK_STATE_RENEW_MS
    if not should_send:
        return

    if await _push_lock_state(anchor_id, True, evt):
        _anchor_lock_decision[anchor_id] = True
        _anchor_lock_last_sent_ms[anchor_id] = now_ms
        evt["lock_command_sent"] = True


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
        cfg["anchor_id_str"] = str(anchor_id)
        cfg["ts_ms"]     = evt.get("ts_ms", int(time.time() * 1000))
        return cfg  # caller broadcasts this

    # ── High-frequency types — skip history insert, skip anchor heartbeat ──
    if etype in _HIGH_FREQ_TYPES:
        # For live ranging samples: rate-limited tag_state write so the snapshot stays fresh
        if etype in ("EVT_RTLS_UPDATE", "EVT_TWR_SAMPLE"):
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
                                        gear=evt.get("gear"), escort=evt.get("escort", 0),
                                        x_cm=evt.get("x_cm"), y_cm=evt.get("y_cm"),
                                        room_id=evt.get("room_id"),
                                        global_x_cm=evt.get("global_x_cm"),
                                        global_y_cm=evt.get("global_y_cm"),
                                        source_anchor=evt.get("source_anchor"))
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

    bootstrap_pending = anchor_id_cert == 0
    if bootstrap_pending:
        log.info("[TCP] Bootstrap anchor connected from %s — waiting for HELLO EUI",
                 peer)
    else:
        log.info("[TCP] Anchor %d connected from %s (cert serial …%s)",
                 anchor_id_cert, peer, serial_hex[-8:])

        _anchor_writers[anchor_id_cert] = writer

        cfg = db.get_anchor_config(anchor_id_cert)
        _anchor_lock_distance_cm[anchor_id_cert] = int(
            cfg.get("lock_distance_cm") or _DEFAULT_LOCK_DISTANCE_CM
        )
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
            while buffer:
                if buffer[0] == _RAW_TWR_START:
                    if len(buffer) < _RAW_TWR_FRAME_LEN:
                        break
                    frame, buffer = buffer[:_RAW_TWR_FRAME_LEN], buffer[_RAW_TWR_FRAME_LEN:]
                    if bootstrap_pending:
                        log.debug("[TCP] Dropped raw TWR frame from bootstrap peer before HELLO")
                        continue
                    evt = _decode_raw_twr_frame(frame)
                    if evt is None:
                        continue
                    etype = evt.get("type", "")
                    evt["ts_ms"] = int(time.time() * 1000)
                    evt["anchor_id"] = anchor_id_cert
                    evt["anchor_id_str"] = str(anchor_id_cert)

                    await _apply_twr_lock_decision(anchor_id_cert, evt)

                    if _broadcast_fn:
                        _broadcast_fn(evt)

                    if event_queue is not None:
                        try:
                            event_queue.put_nowait(evt)
                        except asyncio.QueueFull:
                            pass

                    loop.run_in_executor(None, _persist_event, evt.copy())
                    continue

                if b"\n" not in buffer:
                    break
                line, buffer = buffer.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    evt   = json.loads(line.decode("utf-8"))
                    etype = evt.get("type", "")
                    if bootstrap_pending:
                        if etype != "HELLO":
                            log.warning("[TCP] Bootstrap anchor from %s sent %s before HELLO; ignoring",
                                        peer, etype or "UNKNOWN")
                            continue

                        hello_eui = _extract_hello_eui(evt)
                        if hello_eui is None:
                            log.warning("[TCP] Bootstrap HELLO from %s missing valid EUI — raw: %s",
                                        peer, line[:120])
                            writer.close()
                            return

                        anchor_id_cert = hello_eui
                        bootstrap_pending = False
                        _anchor_writers[anchor_id_cert] = writer
                        log.info("[TCP] Bootstrap HELLO from %s — using EUI %016X (%d)",
                                 peer, anchor_id_cert, anchor_id_cert)

                        try:
                            cert = pki_utils.generate_anchor_cert(anchor_id_cert, PKI_DIR)
                        except Exception as e:
                            log.error("[TCP] Bootstrap cert generation failed for anchor %d: %s",
                                      anchor_id_cert, e)
                            writer.close()
                            return

                        _pending_reprovisions[anchor_id_cert] = cert["serial_hex"]
                        await push_command(anchor_id_cert, {
                            "type":        "REPROVISION",
                            "anchor_id":   anchor_id_cert,
                            "ca_cert":     cert["ca_cert_pem"],
                            "client_cert": cert["client_cert_pem"],
                            "client_key":  cert["client_key_pem"],
                        })

                        cfg = db.get_anchor_config(anchor_id_cert)
                        _anchor_lock_distance_cm[anchor_id_cert] = int(
                            cfg.get("lock_distance_cm") or _DEFAULT_LOCK_DISTANCE_CM
                        )
                        if cfg.get("config_status") == "PENDING":
                            await push_config(anchor_id_cert, cfg)

                    if etype == "HELLO":
                        hello_payload = evt.get("payload", evt)
                        log.info("[TCP] HELLO from anchor %d via TCP — payload=%s",
                                 anchor_id_cert,
                                 json.dumps(hello_payload, separators=(",", ":")))
                    evt["ts_ms"]    = int(time.time() * 1000)
                    evt["anchor_id"] = anchor_id_cert
                    evt["anchor_id_str"] = str(anchor_id_cert)

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

                    # Server-side door decision for immediate TWR samples.
                    await _apply_twr_lock_decision(anchor_id_cert, evt)

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
        _anchor_lock_decision.pop(anchor_id_cert, None)
        _anchor_lock_last_sent_ms.pop(anchor_id_cert, None)
        _anchor_twr_tags.pop(anchor_id_cert, None)
        task = _anchor_twr_expiry_tasks.pop(anchor_id_cert, None)
        if task:
            task.cancel()
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
