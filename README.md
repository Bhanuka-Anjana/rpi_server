# WMS Local Server — RPi 4B Setup

## RPi First-Time Setup

```bash
# 1. Set static IP — edit /etc/dhcpcd.conf
interface eth0
static ip_address=192.168.1.100/24
static routers=192.168.1.1
static domain_name_servers=8.8.8.8

# 2. Install Python
sudo apt update && sudo apt install -y python3 python3-pip python3-venv

# 3. Copy project to RPi
scp -r rpi_server/ pi@192.168.1.100:/home/pi/wms_server

# 4. Create virtualenv and install deps
cd /home/pi/wms_server
python3 -m venv venv
venv/bin/pip install -r requirements.txt
```

## Configure ProtoNest Connect credentials

Edit `config.py`:
```python
MQTT_BROKER_HOST = "your.protonest.host"
MQTT_USERNAME    = "your_username"
MQTT_PASSWORD    = "your_password"
```

## Run manually (test)
```bash
cd /home/pi/wms_server
venv/bin/python main.py
```

Open browser: `http://192.168.1.100:8080`

## Install as systemd service (auto-start)
```bash
sudo cp wms-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable wms-server
sudo systemctl start wms-server

# Check status
sudo systemctl status wms-server
journalctl -u wms-server -f
```

## Anchor TCP connection (firmware S3-A)
Each anchor connects via TCP to `192.168.1.100:5005` and sends:
```
{"anchor_id":1,"type":"EVT_DOOR_LOCKED","tag_uid":4660,"dist_cm":210,"ts_ms":1234567890}\n
```

## Dashboard
- Live tag status:  `http://192.168.1.100:8080`
- REST API docs:    `http://192.168.1.100:8080/docs`
