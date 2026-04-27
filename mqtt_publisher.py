# mqtt_publisher.py — ProtoNest Connect MQTT publisher (RPi → Cloud)
#
# Reads events from the shared asyncio queue (filled by tcp_server).
# Publishes to ProtoNest Connect broker.
# On disconnect: events remain in SQLite (mqtt_sent=0).
# On reconnect: drains the SQLite retry queue before processing live events.

import asyncio
import json
import logging

import paho.mqtt.client as mqtt

import database as db
from config import (
    MQTT_BROKER_HOST, MQTT_BROKER_PORT,
    MQTT_USERNAME, MQTT_PASSWORD,
    MQTT_CLIENT_ID, MQTT_TOPIC_PREFIX,
    MQTT_RETRY_INTERVAL_S, MQTT_USE_TLS,
)

log = logging.getLogger("mqtt_publisher")

# MQTT topic builders
def _topic_event(anchor_id: int) -> str:
    return f"{MQTT_TOPIC_PREFIX}/anchor/{anchor_id}/event"

def _topic_heartbeat(anchor_id: int) -> str:
    return f"{MQTT_TOPIC_PREFIX}/anchor/{anchor_id}/heartbeat"

def _topic_config_applied(anchor_id: int) -> str:
    """Published (retained) when anchor acknowledges a CONFIG push.
    Topic: wms/anchor/{id}/config/applied
    Payload excludes WiFi passwords and internal server fields.
    """
    return f"{MQTT_TOPIC_PREFIX}/anchor/{anchor_id}/config/applied"

def _topic_alert() -> str:
    return f"{MQTT_TOPIC_PREFIX}/alert"

ALERT_TYPES = {"EVT_FIRE_ALARM", "EVT_FIRE_CLEARED", "EVT_ALARM_DOOR_FORCED",
               "EVT_ALARM_UNAUTHORIZED", "EVT_TAG_LOST"}

# Strip these server-internal fields before publishing any MQTT payload.
# wifi_networks is excluded to prevent WiFi passwords from reaching the cloud.
_MQTT_STRIP = frozenset({
    "config_status", "updated_ms", "config_updated_ms", "_db_id", "wifi_networks",
})

def _pick_topic(evt: dict) -> str:
    etype = evt.get("type", "")
    anchor_id = evt.get("anchor_id", 0)
    if etype == "EVT_HEARTBEAT":
        return _topic_heartbeat(anchor_id)
    if etype == "CONFIG_APPLIED":
        return _topic_config_applied(anchor_id)
    if etype in ALERT_TYPES:
        return _topic_alert()
    return _topic_event(anchor_id)


class MqttPublisher:
    def __init__(self):
        self._client = mqtt.Client(client_id=MQTT_CLIENT_ID)
        self._client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
        self._client.on_connect    = self._on_connect
        self._client.on_disconnect = self._on_disconnect
        self._client.on_message    = self._on_message
        self._connected = False
        self._loop = None   # asyncio event loop, set in run()

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            self._connected = True
            log.info("[MQTT] Connected to ProtoNest Connect")
            # Subscribe to config and command topics from cloud portal
            client.subscribe(f"{MQTT_TOPIC_PREFIX}/anchor/+/config",  qos=1)
            client.subscribe(f"{MQTT_TOPIC_PREFIX}/anchor/+/command", qos=1)
        else:
            self._connected = False
            log.warning("[MQTT] Connection failed rc=%d", rc)

    # Downlink commands that cloud portal can send
    DOWNLINK_COMMANDS = {"EVT_FIRE_CLEARED"}

    def _on_message(self, client, userdata, msg):
        """Handle incoming messages from cloud portal."""
        try:
            parts     = msg.topic.split("/")
            anchor_id = int(parts[parts.index("anchor") + 1])
            payload   = json.loads(msg.payload.decode())

            # ── Config push ──────────────────────────────────────────
            if msg.topic.endswith("/config"):
                nets_in = payload.get("wifi_networks", [])
                log.info("[MQTT] Config received for anchor %d — wifi_networks=%d %s",
                         anchor_id, len(nets_in) if isinstance(nets_in, list) else "?",
                         [n.get("ssid") for n in nets_in] if isinstance(nets_in, list) else nets_in)
                cfg = db.upsert_anchor_config(anchor_id, payload)
                nets_saved = cfg.get("wifi_networks", [])
                log.info("[MQTT] Config stored for anchor %d — wifi_networks=%d saved",
                         anchor_id, len(nets_saved))
                if self._loop:
                    import tcp_server
                    asyncio.run_coroutine_threadsafe(
                        tcp_server.push_config(anchor_id, cfg), self._loop
                    )

            # ── Downlink command (e.g. EVT_FIRE_CLEARED) ─────────────
            elif msg.topic.endswith("/command"):
                cmd_type = payload.get("type", "")
                if cmd_type not in self.DOWNLINK_COMMANDS:
                    log.warning("[MQTT] Unknown command type: %s", cmd_type)
                    return
                log.info("[MQTT] Command %s → anchor %d", cmd_type, anchor_id)
                cmd = {"type": cmd_type, "anchor_id": anchor_id}
                if self._loop:
                    import tcp_server
                    asyncio.run_coroutine_threadsafe(
                        tcp_server.push_command(anchor_id, cmd), self._loop
                    )

        except Exception as e:
            log.warning("[MQTT] Message parse error: %s", e)

    def _on_disconnect(self, client, userdata, rc):
        self._connected = False
        log.warning("[MQTT] Disconnected rc=%d — buffering to SQLite", rc)

    def _connect(self):
        if not MQTT_BROKER_HOST:
            log.warning("[MQTT] Broker host not configured — skipping connection")
            return
        try:
            if MQTT_USE_TLS:
                import ssl
                self._client.tls_set(cert_reqs=ssl.CERT_NONE)
                self._client.tls_insecure_set(True)
            self._client.connect(MQTT_BROKER_HOST, MQTT_BROKER_PORT, keepalive=60)
            self._client.loop_start()
        except Exception as e:
            log.error("[MQTT] Connect error: %s", e)

    def _publish(self, evt: dict) -> bool:
        if not self._connected:
            return False
        topic  = _pick_topic(evt)
        etype  = evt.get("type", "")
        retain = etype in ALERT_TYPES or etype == "CONFIG_APPLIED"
        # Strip internal / sensitive fields before publishing
        pub_evt = {k: v for k, v in evt.items() if k not in _MQTT_STRIP}
        payload = json.dumps(pub_evt)
        result  = self._client.publish(topic, payload, qos=1, retain=retain)
        if result.rc == mqtt.MQTT_ERR_SUCCESS:
            db_id = evt.get("_db_id")
            if db_id:
                db.mark_mqtt_sent(db_id)
            log.debug("[MQTT] Published %s → %s", evt.get("type"), topic)
            return True
        return False

    def _drain_retry_queue(self):
        """Publish any events that were stored while offline."""
        unsent = db.get_unsent_events(limit=50)
        if not unsent:
            return
        log.info("[MQTT] Draining %d buffered events", len(unsent))
        for row in unsent:
            evt = json.loads(row["payload_json"])
            evt["_db_id"] = row["id"]
            if not self._publish(evt):
                break  # Still offline — stop draining

    async def run(self, queue: asyncio.Queue):
        self._loop = asyncio.get_event_loop()
        self._connect()

        retry_timer = 0.0

        while True:
            now = asyncio.get_event_loop().time()

            # Periodically drain SQLite retry queue
            if self._connected and (now - retry_timer) > MQTT_RETRY_INTERVAL_S:
                retry_timer = now
                await asyncio.get_event_loop().run_in_executor(
                    None, self._drain_retry_queue
                )

            # Process live events from TCP server
            try:
                evt = await asyncio.wait_for(queue.get(), timeout=1.0)
                if not self._publish(evt):
                    log.debug("[MQTT] Offline — event id=%s buffered in DB",
                              evt.get("_db_id"))
                queue.task_done()
            except asyncio.TimeoutError:
                pass

            # Reconnect if disconnected
            if not self._connected and MQTT_BROKER_HOST:
                log.info("[MQTT] Attempting reconnect...")
                self._connect()
                await asyncio.sleep(5)
