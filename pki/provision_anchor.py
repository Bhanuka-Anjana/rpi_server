#!/usr/bin/env python3
"""
provision_anchor.py — Generate a unique mTLS certificate for one WMS anchor.

Produces a folder ready to copy to the anchor's SD card root:

    <out_dir>/wms_creds/
        ca.crt        — Root CA cert  (anchor pins this to verify the server)
        anchor.crt    — Anchor client cert  (signed by the WMS CA)
        anchor.key    — Anchor private key

On first boot the anchor reads these files, writes them to NVS, then deletes
them from the SD card.

Usage (from rpi_server/ directory):
    python3 pki/provision_anchor.py --id 1
    python3 pki/provision_anchor.py --id 2 --out /media/usb/sdprep
    python3 pki/provision_anchor.py --id 3 --pki-dir /etc/wms/pki --out /tmp/sd_prep
"""

import argparse
import os
import shutil
import stat
import sys

# Allow imports from the parent rpi_server/ directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import database as db
import pki_utils


def provision(anchor_id: int, out_dir: str, pki_dir: str):
    db.init_db()   # no-op if already initialised
    cert = pki_utils.generate_anchor_cert(anchor_id, pki_dir)

    # ── Write SD card prep folder ────────────────────────────────────
    creds_dir = os.path.join(out_dir, "wms_creds")
    os.makedirs(creds_dir, exist_ok=True)

    # ca.crt — the anchor trusts this to verify the server
    shutil.copy(os.path.join(pki_dir, "ca.crt"), os.path.join(creds_dir, "ca.crt"))

    # anchor.crt
    with open(os.path.join(creds_dir, "anchor.crt"), "w") as f:
        f.write(cert["client_cert_pem"])

    # anchor.key — private key, protect it
    key_path = os.path.join(creds_dir, "anchor.key")
    with open(key_path, "w") as f:
        f.write(cert["client_key_pem"])
    os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)  # 600

    print(f"[PROVISION] Anchor ID  : {anchor_id}  (CN={anchor_id})")
    print(f"[PROVISION] Cert serial: {cert['serial_hex']}")
    print(f"[PROVISION] SD prep    : {creds_dir}/")
    print()
    print("[PROVISION] Next steps:")
    print(f"  1. Copy the  wms_creds/  folder to the root of the anchor SD card.")
    print(f"  2. Insert the SD card into the anchor and power it on.")
    print(f"  3. On first boot the anchor reads the certs, stores them in NVS,")
    print(f"     deletes the files, then reboots into normal operation.")
    print()
    print("[PROVISION] To revoke this anchor later:")
    print(f"  >>> import database as db")
    print(f"  >>> db.revoke_anchor_cert('{cert['serial_hex']}')")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Provision a unique mTLS certificate for a WMS anchor."
    )
    ap.add_argument(
        "--id", required=True, type=int,
        help="Anchor ID (integer, must match the NVS anchor_id on the device)"
    )
    ap.add_argument(
        "--out", default="/tmp/sd_prep",
        help="Output directory for SD card prep (default: /tmp/sd_prep)"
    )
    ap.add_argument(
        "--pki-dir", default="/etc/wms/pki",
        help="PKI directory containing ca.key and ca.crt (default: /etc/wms/pki)"
    )
    args = ap.parse_args()
    provision(args.id, args.out, args.pki_dir)
