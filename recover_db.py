#!/usr/bin/env python3
"""
recover_db.py — One-shot DB recovery after wms.db is accidentally deleted.

The CA keys and anchor NVS certs are still intact, but the anchor_certs ledger
is gone, so the server rejects every anchor connection.

This script:
  1. Re-initialises the DB tables (no-op if already done by a server start).
  2. Re-registers the bootstrap cert (CN=0) from bootstrap/anchor.crt.
  3. Patches tcp_server to auto-register any anchor cert that passes the mTLS
     handshake (signed by our CA) instead of rejecting unknown serials.
  4. Starts the full server — anchors reconnect, serials land back in the DB.
  5. Prints a "safe to restart normally" message once each anchor is seen.

Run ONCE, wait until all anchors show "registered", then Ctrl-C and restart
the server normally (python main.py or systemctl restart wms-server).
"""

import asyncio
import logging
import os
import sys

# ── Bootstrap cert re-registration ───────────────────────────────────────────

BOOTSTRAP_CERT = os.path.join(os.path.dirname(__file__), "bootstrap", "anchor.crt")


def _register_bootstrap():
    try:
        from cryptography import x509
    except ImportError:
        print("[RECOVER] 'cryptography' package not found — run: pip install cryptography")
        sys.exit(1)

    import database as db
    db.init_db()

    with open(BOOTSTRAP_CERT, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    serial_hex = f"{cert.serial_number:040X}"
    db.register_anchor_cert(0, serial_hex)
    print(f"[RECOVER] Bootstrap cert (CN=0) registered — serial {serial_hex[-12:]}…")
    return serial_hex


# ── Permissive cert check patch ───────────────────────────────────────────────
# Replace is_cert_revoked so that any cert that passed the TLS handshake
# (i.e. signed by our CA) is auto-registered and allowed through.

def _patch_cert_check():
    import database as db
    import tcp_server

    _registered = set()

    def _permissive_check(serial_hex: str) -> bool:
        if serial_hex in _registered:
            return False  # already seen this session

        # We don't know the anchor_id yet — it's read by _extract_anchor_id
        # separately and stored in the ledger by the handler below.
        # Here we just allow the connection through; the handler patches DB.
        _registered.add(serial_hex)
        return False  # False = "not revoked" = allow

    db.is_cert_revoked = _permissive_check

    # Also patch _handle_anchor so new serials land in the DB
    _orig_handle = tcp_server._handle_anchor

    async def _recovery_handle(reader, writer):
        import tcp_server as _tcp
        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj:
            cert = ssl_obj.getpeercert()
            if cert:
                subject = dict(x[0] for x in cert.get("subject", ()))
                cn = subject.get("commonName", "?")
                try:
                    anchor_id = int(cn)
                except ValueError:
                    anchor_id = -1

                serial_raw = cert.get("serialNumber", "0")
                try:
                    serial_hex = f"{int(serial_raw, 16):040X}"
                except ValueError:
                    serial_hex = f"{int(serial_raw):040X}"

                if anchor_id >= 0 and serial_hex not in _registered:
                    db.register_anchor_cert(anchor_id, serial_hex)
                    _registered.add(serial_hex)
                elif anchor_id >= 0:
                    # Seen serial but may not be in DB yet if first call was permissive_check
                    try:
                        db.register_anchor_cert(anchor_id, serial_hex)
                    except Exception:
                        pass

                if anchor_id > 0:
                    print(f"[RECOVER] ✓ Anchor {anchor_id} re-registered "
                          f"(serial …{serial_hex[-8:]})")
                elif anchor_id == 0:
                    print(f"[RECOVER] Bootstrap anchor connected — "
                          f"zero-touch will assign a new ID")

        await _orig_handle(reader, writer)

    tcp_server._handle_anchor = _recovery_handle
    print("[RECOVER] Permissive cert mode active — "
          "all CA-verified anchors will be auto-registered")


# ── Main ──────────────────────────────────────────────────────────────────────

async def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-7s  %(message)s",
        datefmt="%H:%M:%S",
    )

    print()
    print("=" * 60)
    print("  WMS DB RECOVERY MODE")
    print("  Wait until all anchors show ✓, then Ctrl-C.")
    print("  Restart the server normally afterwards.")
    print("=" * 60)
    print()

    _register_bootstrap()
    _patch_cert_check()

    import database as db
    from api import app, broadcast_event
    from config import API_HOST, API_PORT
    from mqtt_publisher import MqttPublisher
    from tcp_server import run_tcp_server
    import uvicorn
    import api as _api
    import tcp_server as _tcp

    db.init_db()
    queue: asyncio.Queue = asyncio.Queue(maxsize=200)

    loop = asyncio.get_running_loop()
    _api._main_loop = loop
    _tcp._loop      = loop

    _orig_process = _tcp._process_event

    def _patched(evt):
        _orig_process(evt)
        broadcast_event(evt)

    _tcp._process_event = _patched

    config = uvicorn.Config(app, host=API_HOST, port=API_PORT,
                            log_level="warning", access_log=False)
    server = uvicorn.Server(config)
    publisher = MqttPublisher()

    await asyncio.gather(
        run_tcp_server(queue),
        publisher.run(queue),
        server.serve(),
    )


if __name__ == "__main__":
    asyncio.run(main())
