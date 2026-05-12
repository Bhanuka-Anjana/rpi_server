# pki_utils.py — Shared PKI utilities for WMS anchor certificate generation.
#
# Used by:
#   pki/provision_anchor.py  — SD card provisioning (manual, one anchor at a time)
#   pki/generate_bootstrap.py — shared bootstrap cert embedded in firmware
#   tcp_server.py             — zero-touch auto-provisioning on first connect
#   api.py                    — OTA re-provisioning endpoint

import os
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

# Allow running from any working directory — database is in the same folder
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import database as db

_NO_EXPIRY = datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)


def _load_ca(pki_dir: str):
    ca_key_path  = os.path.join(pki_dir, "ca.key")
    ca_cert_path = os.path.join(pki_dir, "ca.crt")
    if not os.path.exists(ca_key_path):
        raise FileNotFoundError(
            f"CA key not found at {ca_key_path} — run pki/generate_ca.py first"
        )
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    return ca_key, ca_cert


def generate_anchor_cert(anchor_id: int, pki_dir: str) -> dict:
    """
    Generate an EC P-256 anchor certificate (CN=EUI-64 hex), signed by the site CA.
    Registers the cert serial in the DB immediately so concurrent bootstrap handlers
    can detect the anchor_id as taken.

    anchor_id must be the EUI-64 numeric value (uint64).  anchor_id=0 is reserved
    for the shared bootstrap cert (factory-fresh devices, CN='0').

    Returns:
        {
            "serial_hex":      "...",   # 40-char uppercase hex
            "ca_cert_pem":     "...",   # PEM string
            "client_cert_pem": "...",   # PEM string
            "client_key_pem":  "...",   # PEM string
        }
    """
    ca_key, ca_cert = _load_ca(pki_dir)
    now = datetime.now(timezone.utc)

    anchor_key  = ec.generate_private_key(ec.SECP256R1())
    # CN = 16-char uppercase hex of EUI-64 (e.g. "A4C138FFFEAABBCC").
    # Bootstrap cert (anchor_id=0) keeps CN='0' as the sentinel.
    cn_str = "0" if anchor_id == 0 else f"{anchor_id:016X}"
    anchor_name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "WMS"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn_str),
    ])

    serial = x509.random_serial_number()
    anchor_cert = (
        x509.CertificateBuilder()
        .subject_name(anchor_name)
        .issuer_name(ca_cert.subject)
        .public_key(anchor_key.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(_NO_EXPIRY)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    serial_hex      = f"{serial:040X}"
    ca_cert_pem     = open(os.path.join(pki_dir, "ca.crt")).read()
    client_cert_pem = anchor_cert.public_bytes(serialization.Encoding.PEM).decode()
    client_key_pem  = anchor_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    # Register in DB immediately so concurrent bootstrap handlers can detect
    # this anchor_id as already provisioned (cert serial in anchor_certs).
    db.register_anchor_cert(anchor_id, serial_hex)

    return {
        "serial_hex":      serial_hex,
        "ca_cert_pem":     ca_cert_pem,
        "client_cert_pem": client_cert_pem,
        "client_key_pem":  client_key_pem,
    }
