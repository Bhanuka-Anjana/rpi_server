# config.py — WMS Local Server Configuration

# ── TCP Server (Anchor → RPi) ─────────────────────────────────────────
TCP_HOST = "0.0.0.0"   # Listen on all interfaces
TCP_PORT = 5005         # Anchors connect to RPi_IP:5005

# ── ProtoNest Connect (RPi → Cloud MQTT) ─────────────────────────────
MQTT_BROKER_HOST  = "mqtt.protonest.co"                    # Fill in broker hostname
MQTT_BROKER_PORT  = 8883                  # TLS port
MQTT_USERNAME     = "test-protonest#5dec"
MQTT_PASSWORD     = "Test@#Protonest%01@20"
MQTT_CLIENT_ID    = "test-protonest#5dec"
MQTT_TOPIC_PREFIX = "wms"
MQTT_USE_TLS      = True

# ── Database ──────────────────────────────────────────────────────────
DB_PATH = "wms.db"

# ── Web Dashboard (REST API) ──────────────────────────────────────────
API_HOST = "0.0.0.0"
API_PORT = 8080

# ── Offline buffer retry interval (seconds) ──────────────────────────
MQTT_RETRY_INTERVAL_S  = 10
MQTT_CONNECT_TIMEOUT_S = 5    # Socket connect timeout (reduces startup delay)

# ── Time ──────────────────────────────────────────────────────────────
# UTC offset sent to anchors for local clock display.
# Format: "+H:MM" or "-H:MM"  e.g. "+5:30" for Sri Lanka, "+0:00" for UTC
UTC_OFFSET = "+5:30"

# ── OTA Firmware ──────────────────────────────────────────────────────
# Leave empty to auto-detect the RPi's LAN IP at runtime.
# Set explicitly if the RPi has multiple interfaces or a known hostname.
OTA_BASE_URL = ""   # e.g. "http://192.168.1.10:8080"

# ── PKI (mTLS) ────────────────────────────────────────────────────────
# Run  pki/generate_ca.py  once before first anchor is provisioned.
# Run  pki/provision_anchor.py --id <N>  for each new anchor.
PKI_DIR          = "/etc/wms/pki"
CA_CERT_PATH     = PKI_DIR + "/ca.crt"
CA_KEY_PATH      = PKI_DIR + "/ca.key"
SERVER_CERT_PATH = PKI_DIR + "/server.crt"
SERVER_KEY_PATH  = PKI_DIR + "/server.key"
