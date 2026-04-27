#!/usr/bin/env python3
"""
generate_bootstrap.py — Generate the shared bootstrap certificate for zero-touch
provisioning.

The bootstrap cert (CN=0) is shared across all factory-fresh anchors and is
embedded in the firmware binary at build time via CMake EMBED_TXTFILES.

Run once per site, after generate_ca.py:
    venv/bin/python pki/generate_bootstrap.py

Output files (written relative to the wms_fw/ repo root):
    anchor_esp_idf/main/bootstrap/ca.crt
    anchor_esp_idf/main/bootstrap/anchor.crt
    anchor_esp_idf/main/bootstrap/anchor.key

After running this script:
  1. Rebuild the ESP32 firmware — the certs are compiled in via EMBED_TXTFILES.
  2. Flash the firmware to all factory-fresh anchors (no SD card needed).
  3. On first power-on the anchor connects with the bootstrap cert (CN=0).
     The server detects CN=0, auto-assigns a unique anchor_id, and pushes a
     real per-anchor REPROVISION message.  The anchor writes the new creds to
     NVS and reboots as anchor_id=N — provisioning complete.

WARNING: Re-running this script generates a NEW bootstrap cert with a new serial.
         The old bootstrap cert will still be in the DB with revoked=0.
         If you want to prevent old bootstrap firmware from connecting, revoke the
         old serial manually:
           python3 -c "import database as db; db.revoke_anchor_cert('<old_serial>')"
"""

import os
import stat
import sys

# Allow imports from the parent rpi_server/ directory
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_RPI_DIR    = os.path.dirname(_SCRIPT_DIR)          # rpi_server/
_REPO_ROOT  = os.path.dirname(_RPI_DIR)             # wms_fw/
sys.path.insert(0, _RPI_DIR)

import database as db
import pki_utils
from config import PKI_DIR

_BOOTSTRAP_DIR = os.path.join(_REPO_ROOT, "rpi_server",  "bootstrap")


def main():
    print("[BOOTSTRAP] Generating shared bootstrap certificate (CN=0) …")
    db.init_db()

    cert = pki_utils.generate_anchor_cert(0, PKI_DIR)

    os.makedirs(_BOOTSTRAP_DIR, exist_ok=True)

    # ca.crt — the site root CA (anchor pins this to verify the server)
    import shutil
    shutil.copy(os.path.join(PKI_DIR, "ca.crt"),
                os.path.join(_BOOTSTRAP_DIR, "ca.crt"))

    # anchor.crt — the shared bootstrap client cert (CN=0)
    with open(os.path.join(_BOOTSTRAP_DIR, "anchor.crt"), "w") as f:
        f.write(cert["client_cert_pem"])

    # anchor.key — the shared bootstrap private key
    key_path = os.path.join(_BOOTSTRAP_DIR, "anchor.key")
    with open(key_path, "w") as f:
        f.write(cert["client_key_pem"])
    os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)  # 600

    print(f"[BOOTSTRAP] Serial    : {cert['serial_hex']}")
    print(f"[BOOTSTRAP] Output    : {_BOOTSTRAP_DIR}/")
    print()
    print("[BOOTSTRAP] Next steps:")
    print("  1. Rebuild the ESP32 firmware (certs baked in via EMBED_TXTFILES).")
    print("  2. Flash to all factory-fresh anchors — no SD card needed.")
    print("  3. On power-on the anchor connects with the bootstrap cert,")
    print("     the server auto-assigns a unique anchor_id and pushes a real cert.")
    print("     The anchor saves the new creds to NVS and reboots.")


if __name__ == "__main__":
    main()
