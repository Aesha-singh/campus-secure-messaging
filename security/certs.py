"""Local CA + server/client X.509 certificate tooling and TLS context builders.

Networking concept demonstrated
-------------------------------
**PKI / trust model behind TLS.**  TLS 1.3 authenticates endpoints using
certificates chained to a CA:

* **Certification Authority** -- a self-signed root we create once; its
  private key must live offline.  It signs leaves with the **CA:TRUE** Basic
  Constraint so nothing else can mint certificates in our domain.
* **Subject Alternative Names** -- server certs list every DNS/IP it serves
  (``localhost``, ``127.0.0.1``, ``::1``, the hostname); the client verifies
  the presented SAN matches the name it expects (hostname/pinning via IP).
* **Extended Key Usage** -- ``serverAuth`` / ``clientAuth`` restrict a cert to
  one role, a first line of defence if a cert leaks.
* **Trust store + verification** -- the client/peer pins the CA cert,
  validates the chain, checks validity windows, and (optionally) demands a
  signed client certificate (mutual TLS / "mTLS"), giving true machine
  authentication instead of just password authentication.

Run: ``python -m security.certs --outdir security/certs --host myhost campus.example``
"""

from __future__ import annotations

import argparse
import datetime
import ipaddress
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

CA_VALIDITY_DAYS = 3650
LEAF_VALIDITY_DAYS = 365
SERIAL_SUFFIX = b"CSCP-v1"


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


def make_ca(name: str) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Create a self-signed root CA key pair + certificate."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, name), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CSCP Campus")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - datetime.timedelta(days=1))
        .not_valid_after(_now() + datetime.timedelta(days=CA_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("CSCP Campus CA")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def make_leaf(
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    *,
    common_name: str,
    dns_names: Sequence[str],
    ip_addresses: Sequence[str],
    kind: str = "server",
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Create a leaf certificate signed by the CA.

    ``kind`` selects the Extended Key Usage: ``server``/``client``/``both``.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    eku: list[ObjectIdentifier] = []
    if kind in ("server", "both"):
        eku.append(ExtendedKeyUsageOID.SERVER_AUTH)
    if kind in ("client", "both"):
        eku.append(ExtendedKeyUsageOID.CLIENT_AUTH)
    sans = [x509.DNSName(n) for n in dns_names if n] + [
        x509.IPAddress(ipaddress.ip_address(ip)) for ip in ip_addresses if ip
    ]
    builder = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CSCP Campus"),
                ]
            )
        )
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - datetime.timedelta(days=1))
        .not_valid_after(_now() + datetime.timedelta(days=LEAF_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True, key_agreement=True,
                                     content_commitment=False, key_cert_sign=False, crl_sign=False,
                                     data_encipherment=False, encipher_only=False, decipher_only=False), critical=True)
    )
    if eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    cert = builder.sign(ca_key, hashes.SHA256())
    return key, cert


def _write_priv(key: ec.EllipticCurvePrivateKey, path: Path) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)


def _write_cert(cert: x509.Certificate, path: Path) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def ensure_ca(outdir: Path, *, name: str = "CSCP Campus Root CA") -> tuple[Path, Path]:
    """Idempotently create (skips if present) ``ca.key`` + ``ca.pem`` under ``outdir``."""
    outdir.mkdir(parents=True, exist_ok=True)
    key_path, cert_path = outdir / "ca.key", outdir / "ca.pem"
    if key_path.exists() and cert_path.exists():
        return key_path, cert_path
    key, cert = make_ca(name)
    _write_priv(key, key_path)
    _write_cert(cert, cert_path)
    return key_path, cert_path


def ensure_leaf(
    outdir: Path,
    *,
    ca_key: Path,
    ca_cert: Path,
    common_name: str,
    dns_names: Sequence[str] = (),
    ip_addresses: Sequence[str] = (),
    kind: str = "server",
    stem: str,
) -> tuple[Path, Path]:
    """Create (or reuse) a leaf ``stem.key`` + ``stem.pem`` signed by the CA."""
    outdir.mkdir(parents=True, exist_ok=True)
    key_path, cert_path = outdir / f"{stem}.key", outdir / f"{stem}.pem"
    if key_path.exists() and cert_path.exists():
        return key_path, cert_path
    ca_key_obj = cast(
        ec.EllipticCurvePrivateKey, serialization.load_pem_private_key(ca_key.read_bytes(), password=None)
    )
    ca_cert_obj = x509.load_pem_x509_certificate(ca_cert.read_bytes())
    key, cert = make_leaf(
        ca_key_obj, ca_cert_obj, common_name=common_name, dns_names=dns_names, ip_addresses=ip_addresses, kind=kind
    )
    _write_priv(key, key_path)
    _write_cert(cert, cert_path)
    return key_path, cert_path


@dataclass(slots=True)
class TLSMaterial:
    ca_pem: Path
    cert_pem: Path
    key_pem: Path

    @classmethod
    def from_dir(cls, d: Path, *, peer: str) -> TLSMaterial:
        return cls(ca_pem=d / "ca.pem", cert_pem=d / f"{peer}.pem", key_pem=d / f"{peer}.key")


def load_tls_server_context(material: TLSMaterial, *, require_client_cert: bool = True) -> object:
    """Build an SSLContext that authenticates the server and (optionally) peers.

    Returns an ``ssl.SSLContext`` enforcing TLS 1.3+ with a pinned CA store.
    """
    import ssl

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(cafile=str(material.ca_pem))
    ctx.load_cert_chain(certfile=str(material.cert_pem), keyfile=str(material.key_pem))
    if require_client_cert:
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.verify_mode = ssl.CERT_OPTIONAL
    return ctx


def load_tls_client_context(material: TLSMaterial) -> object:
    """Build an SSLContext for a client pinning our CA and proving identity."""
    import ssl

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(cafile=str(material.ca_pem))
    ctx.load_cert_chain(certfile=str(material.cert_pem), keyfile=str(material.key_pem))
    return ctx


def _default_hosts() -> tuple[list[str], list[str]]:
    import socket

    names = ["localhost", socket.gethostname()]
    try:
        fqdn = socket.getfqdn()
        if fqdn and fqdn not in names:
            names.append(fqdn)
    except OSError:
        pass
    ips = ["127.0.0.1", "::1"]
    try:
        ips.extend(a for a in (socket.gethostbyname_ex(socket.gethostname())[2]) if a not in ips)
    except OSError:
        pass
    return names, ips


def main(argv: Iterable[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Generate CSCP CA + server/client certificates")
    parser.add_argument("--outdir", default="security/certs", type=Path)
    parser.add_argument("--host", action="append", default=None, help="extra DNS SAN, repeatable")
    parser.add_argument("--ip", action="append", default=None, help="extra IP SAN, repeatable")
    parser.add_argument("--client-name", default="cscp-client", help="stem for the client leaf (no per-user creds)")
    args = parser.parse_args(argv)

    dns, ips = _default_hosts()
    dns.extend(args.host or [])
    ips.extend(args.ip or [])
    ca_key, ca_pem = ensure_ca(args.outdir)
    ensure_leaf(
        args.outdir, ca_key=ca_key, ca_cert=ca_pem,
        common_name=args.outdir.name, dns_names=dns, ip_addresses=ips, kind="server", stem="server",
    )
    ensure_leaf(
        args.outdir, ca_key=ca_key, ca_cert=ca_pem,
        common_name=args.client_name, dns_names=[], ip_addresses=[], kind="client", stem=args.client_name,
    )
    print(f"PKI written under {args.outdir}/")


if __name__ == "__main__":  # pragma: no cover
    main()