#!/usr/bin/env python3
"""
generate_ca.py — One-time WMS PKI setup.

Run this ONCE on the RPi before any anchors are provisioned.
Creates the CA and server certificate/key pair.

Usage (from rpi_server/ directory):
    python3 pki/generate_ca.py
    python3 pki/generate_ca.py --pki-dir /etc/wms/pki

Outputs:
    <pki_dir>/ca.key      — CA private key  (keep secret, chmod 600)
    <pki_dir>/ca.crt      — CA certificate  (distributed to anchors via SD card)
    <pki_dir>/server.key  — Server private key  (chmod 600)
    <pki_dir>/server.crt  — Server certificate
"""

import argparse
import os
import stat
import sys
from datetime import datetime, timezone

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
except ImportError:
    print("ERROR: 'cryptography' package not found.")
    print("       Run:  pip install cryptography")
    sys.exit(1)

# Certificates are valid until year 9999 (effectively no expiry)
_NO_EXPIRY = datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)


def _new_ec_key():
    return ec.generate_private_key(ec.SECP256R1())


def _save_key(key, path: str):
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(path, "wb") as f:
        f.write(pem)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 600 — owner read/write only


def _save_cert(cert, path: str):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def generate(pki_dir: str):
    if os.path.exists(os.path.join(pki_dir, "ca.key")):
        print(f"[PKI] ERROR: {pki_dir}/ca.key already exists.")
        print("      Delete the pki directory manually if you want to regenerate.")
        print("      WARNING: regenerating the CA invalidates ALL existing anchor certs.")
        sys.exit(1)

    os.makedirs(pki_dir, exist_ok=True)
    now = datetime.now(timezone.utc)

    # ── CA (self-signed) ─────────────────────────────────────────────
    ca_key = _new_ec_key()
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "WMS"),
        x509.NameAttribute(NameOID.COMMON_NAME, "WMS Root CA"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(_NO_EXPIRY)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # ── Server cert (signed by CA) ───────────────────────────────────
    srv_key = _new_ec_key()
    srv_name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "WMS"),
        x509.NameAttribute(NameOID.COMMON_NAME, "wmsserver"),
    ])
    srv_cert = (
        x509.CertificateBuilder()
        .subject_name(srv_name)
        .issuer_name(ca_name)
        .public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(_NO_EXPIRY)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("wmsserver"),
                x509.DNSName("localhost"),
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    ca_key_path   = os.path.join(pki_dir, "ca.key")
    ca_cert_path  = os.path.join(pki_dir, "ca.crt")
    srv_key_path  = os.path.join(pki_dir, "server.key")
    srv_cert_path = os.path.join(pki_dir, "server.crt")

    _save_key(ca_key,   ca_key_path)
    _save_cert(ca_cert, ca_cert_path)
    _save_key(srv_key,  srv_key_path)
    _save_cert(srv_cert, srv_cert_path)

    print("[PKI] PKI initialised successfully.")
    print(f"  CA cert     : {ca_cert_path}")
    print(f"  CA key      : {ca_key_path}  <-- keep secret")
    print(f"  Server cert : {srv_cert_path}")
    print(f"  Server key  : {srv_key_path}  <-- keep secret")
    print()
    print("[PKI] Next step: provision each anchor with:")
    print("        python3 pki/provision_anchor.py --id <anchor_id>")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Generate the WMS CA and server TLS certificates (run once)."
    )
    ap.add_argument(
        "--pki-dir", default="/etc/wms/pki",
        help="Directory to write CA and server certs/keys (default: /etc/wms/pki)"
    )
    args = ap.parse_args()
    generate(args.pki_dir)
