# main.py — WMS Local Server entry point
#
# Starts three concurrent async components:
#   1. TCP server     — listens for anchor connections on port 5005
#   2. MQTT publisher — forwards events to ProtoNest Connect cloud
#   3. FastAPI server — serves REST API + SSE + web dashboard
#
# Run: python main.py
# Or via systemd: see wms-server.service

import asyncio
import logging

import uvicorn

import database as db
from api import app, broadcast_event
from config import API_HOST, API_PORT
from mqtt_publisher import MqttPublisher
from tcp_server import run_tcp_server

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("main")


async def _tcp_with_broadcast(queue: asyncio.Queue):
    """Wire broadcast_event into the TCP server and start it."""
    import api as _api
    import tcp_server as _tcp

    _api._main_loop = asyncio.get_running_loop()
    _tcp.set_broadcast_fn(broadcast_event)

    await run_tcp_server(queue)


async def main():
    log.info("WMS Local Server starting")

    # Initialise SQLite
    db.init_db()

    # Shared queue: TCP server → MQTT publisher
    queue: asyncio.Queue = asyncio.Queue(maxsize=200)

    # FastAPI via uvicorn (non-blocking)
    config = uvicorn.Config(
        app,
        host=API_HOST,
        port=API_PORT,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)

    publisher = MqttPublisher()

    log.info("Starting TCP server on port 5005")
    log.info("Starting Web dashboard on http://%s:%d", API_HOST, API_PORT)

    await asyncio.gather(
        _tcp_with_broadcast(queue),
        publisher.run(queue),
        server.serve(),
    )


if __name__ == "__main__":
    asyncio.run(main())
