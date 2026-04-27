# api.py — FastAPI REST endpoints + SSE live feed + static dashboard

import asyncio
import hashlib
import json
import time
from pathlib import Path

from fastapi import FastAPI, Request, UploadFile, File, Form
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

import database as db
import pki_utils
import tcp_server
from config import PKI_DIR, OTA_BASE_URL, API_PORT

app = FastAPI(title="WMS Local Server")

# Serve dashboard static files
DASHBOARD_DIR = Path(__file__).parent / "dashboard"
app.mount("/static", StaticFiles(directory=DASHBOARD_DIR), name="static")

# Serve firmware binaries
FIRMWARE_DIR = Path(__file__).parent / "firmware"
FIRMWARE_DIR.mkdir(exist_ok=True)
app.mount("/firmware", StaticFiles(directory=FIRMWARE_DIR), name="firmware")


def _ota_base_url() -> str:
    if OTA_BASE_URL:
        return OTA_BASE_URL.rstrip("/")
    import socket
    try:
        # UDP connect trick: no packets sent, but OS picks the right outbound interface
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return f"http://{ip}:{API_PORT}"

# SSE subscribers — list of asyncio.Queue, one per connected browser tab
_sse_subscribers: list[asyncio.Queue] = []

# Kept for backward compat with recover_db.py — no longer used by main path.
_main_loop = None


def broadcast_event(evt: dict):
    """Push evt to all SSE subscriber queues.

    Always called from the asyncio loop (by _handle_anchor or REST endpoints),
    so put_nowait is safe. When the queue is full, drop the oldest event and
    keep the newest so slow browsers stay connected without stalling the server.
    """
    for q in _sse_subscribers:
        try:
            q.put_nowait(evt)
        except asyncio.QueueFull:
            try:
                q.get_nowait()
            except asyncio.QueueEmpty:
                pass
            try:
                q.put_nowait(evt)
            except asyncio.QueueFull:
                pass


# ── REST endpoints ────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    return (DASHBOARD_DIR / "index.html").read_text()


@app.get("/api/tags")
async def get_tags():
    return db.get_all_tags()


@app.get("/api/anchors")
async def get_anchors():
    return db.get_all_anchors()


@app.get("/api/events")
async def get_events(limit: int = 100):
    return db.get_recent_events(limit)


@app.get("/api/alerts")
async def get_alerts(limit: int = 50):
    return db.get_alerts(limit)


@app.get("/api/anchor/{anchor_id}/config")
async def get_config(anchor_id: int):
    return db.get_anchor_config(anchor_id)


@app.put("/api/anchor/{anchor_id}/config")
async def set_config(anchor_id: int, request: Request):
    params = await request.json()
    cfg = db.upsert_anchor_config(anchor_id, params)
    await tcp_server.push_config(anchor_id, cfg)
    return cfg


@app.get("/api/config/schema")
async def get_config_schema():
    return db.CONFIG_SCHEMA


@app.delete("/api/anchor/{anchor_id}")
async def remove_anchor(anchor_id: int):
    """Manually deregister an anchor — wipes DB records, kicks the live TCP connection,
    and notifies SSE clients.  Any reconnect attempt is rejected at the TLS layer because
    deregister_anchor() deletes the cert ledger rows (unknown serial → revoked)."""
    db.deregister_anchor(anchor_id)
    await tcp_server.kick_anchor(anchor_id)
    broadcast_event({"type": "_anchor_removed", "anchor_id": anchor_id})
    return {"status": "removed", "anchor_id": anchor_id}


@app.post("/api/firmware")
async def upload_firmware(file: UploadFile = File(...), version: str = Form(...)):
    """Upload a .bin firmware image.  Saves to firmware/, computes SHA256, records in DB."""
    data = await file.read()
    sha256 = hashlib.sha256(data).hexdigest()
    filename = f"{version}_{sha256[:8]}.bin"
    (FIRMWARE_DIR / filename).write_bytes(data)
    fw_id = db.insert_firmware(filename, version, len(data), sha256)
    return {"id": fw_id, "filename": filename, "version": version,
            "size_bytes": len(data), "sha256": sha256}


@app.get("/api/firmware")
async def list_firmware():
    return db.get_firmware_files()


@app.delete("/api/firmware/{fw_id}")
async def delete_firmware(fw_id: int):
    fw = db.get_firmware_by_id(fw_id)
    if fw:
        (FIRMWARE_DIR / fw["filename"]).unlink(missing_ok=True)
        db.delete_firmware_record(fw_id)
    return {"status": "deleted", "id": fw_id}


@app.post("/api/anchor/{anchor_id}/ota/start")
async def start_ota(anchor_id: int, fw_id: int):
    """Push OTA_START command to a connected anchor."""
    if anchor_id not in tcp_server._anchor_writers:
        return {"error": "anchor not connected"}
    fw = db.get_firmware_by_id(fw_id)
    if not fw:
        return {"error": "firmware not found"}
    url = f"{_ota_base_url()}/firmware/{fw['filename']}"
    db.set_anchor_ota_status(anchor_id, "IN_PROGRESS", 0)
    tcp_server._pending_ota[anchor_id] = fw_id
    await tcp_server.push_command(anchor_id, {
        "type":    "OTA_START",
        "anchor_id": anchor_id,
        "url":     url,
        "sha256":  fw["sha256"],
        "size":    fw["size_bytes"],
    })
    broadcast_event({"type": "OTA_PROGRESS", "anchor_id": anchor_id, "percent": 0,
                     "ts_ms": int(time.time() * 1000)})
    return {"status": "pushed", "anchor_id": anchor_id, "url": url}


@app.post("/api/anchor/{anchor_id}/reprovision")
async def reprovision_anchor(anchor_id: int):
    """OTA re-provisioning — generates a new cert and pushes it over the live
    mTLS connection.  The anchor writes the new creds to NVS and reboots.
    All previous certs for this anchor are revoked on REPROVISION_ACK."""
    if anchor_id not in tcp_server._anchor_writers:
        return {"error": "anchor not connected"}
    try:
        cert = pki_utils.generate_anchor_cert(anchor_id, PKI_DIR)
    except Exception as e:
        return {"error": str(e)}
    tcp_server._pending_reprovisions[anchor_id] = cert["serial_hex"]
    await tcp_server.push_command(anchor_id, {
        "type":        "REPROVISION",
        "anchor_id":   anchor_id,
        "ca_cert":     cert["ca_cert_pem"],
        "client_cert": cert["client_cert_pem"],
        "client_key":  cert["client_key_pem"],
    })
    return {"status": "pushed", "anchor_id": anchor_id, "serial": cert["serial_hex"]}


@app.get("/api/status")
async def get_status():
    anchors = db.get_all_anchors()
    tags    = db.get_all_tags()
    now_ms  = int(time.time() * 1000)
    online  = sum(1 for a in anchors
                  if a.get("last_heartbeat_ms") and
                  (now_ms - a["last_heartbeat_ms"]) < 120_000)
    active_tags = sum(1 for t in tags
                      if t.get("last_seen_ms") and
                      (now_ms - t["last_seen_ms"]) < 60_000)
    return {
        "anchors_total":  len(anchors),
        "anchors_online": online,
        "tags_active":    active_tags,
        "server_uptime_s": int(time.time()),
    }


# ── Server-Sent Events (live feed to dashboard) ───────────────────────

@app.get("/api/events/stream")
async def event_stream():
    """SSE endpoint — dashboard connects here for live updates."""
    queue: asyncio.Queue = asyncio.Queue(maxsize=200)
    _sse_subscribers.append(queue)

    async def generator():
        try:
            snapshot = {
                "type": "_snapshot",
                "tags": db.get_all_tags(),
                "anchors": db.get_all_anchors(),
            }
            yield f"data: {json.dumps(snapshot)}\n\n"

            while True:
                try:
                    # Wait for the first event (up to 30 s — then send keepalive)
                    evt = await asyncio.wait_for(queue.get(), timeout=30)
                    yield f"data: {json.dumps(evt)}\n\n"

                    # Drain any events that arrived while we were yielding — send
                    # them all in the same TCP segment burst without extra waits.
                    while True:
                        try:
                            evt = queue.get_nowait()
                            yield f"data: {json.dumps(evt)}\n\n"
                        except asyncio.QueueEmpty:
                            break

                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            if queue in _sse_subscribers:
                _sse_subscribers.remove(queue)

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
