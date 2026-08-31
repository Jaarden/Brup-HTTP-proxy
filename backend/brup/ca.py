"""Certificate authority for TLS interception.

A CA key/cert pair is generated once and persisted, so a browser only needs to
trust it a single time. Leaf certificates are minted on demand per hostname and
cached in memory alongside their ready-to-use SSLContext.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import ssl
import tempfile
import threading
import warnings
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CA_NAME = "BRUP Proxy CA"
LEAF_VALID_DAYS = 397  # keep inside the browser-enforced maximum
CA_VALID_DAYS = 3650


def _relax_tls_floor(ctx: ssl.SSLContext) -> None:
    """Allow legacy TLS versions where the OpenSSL build permits it.

    OpenSSL 3.x refuses TLS < 1.2 at the default security level, and raises on
    some builds, so both steps are best-effort.
    """
    try:
        ctx.set_ciphers("DEFAULT@SECLEVEL=0")
    except ssl.SSLError:
        pass
    try:
        with warnings.catch_warnings():
            # Reaching legacy targets is the whole point here.
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = ssl.TLSVersion.TLSv1
    except (ValueError, OSError):
        pass


class CertificateAuthority:
    def __init__(self, directory: Path):
        self.dir = directory
        self.dir.mkdir(parents=True, exist_ok=True)
        self.cert_path = self.dir / "brup-ca.pem"
        self.key_path = self.dir / "brup-ca.key"
        self._lock = threading.Lock()
        self._contexts: dict[str, ssl.SSLContext] = {}
        # Leaf key is reused across hosts: minting an RSA key per host is slow
        # enough to be noticeable on first contact with a site.
        self._leaf_key: rsa.RSAPrivateKey | None = None
        self._tmpdir = Path(tempfile.mkdtemp(prefix="brup-certs-"))
        self._load_or_create()

    # ---------------------------------------------------------------- CA setup
    def _load_or_create(self) -> None:
        if self.cert_path.exists() and self.key_path.exists():
            self.key = serialization.load_pem_private_key(
                self.key_path.read_bytes(), password=None
            )
            self.cert = x509.load_pem_x509_certificate(self.cert_path.read_bytes())
            return
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, CA_NAME),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BRUP"),
        ])
        now = dt.datetime.now(dt.timezone.utc)
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=CA_VALID_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=True, crl_sign=True,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()),
                critical=False,
            )
            .sign(self.key, hashes.SHA256())
        )
        self.cert_path.write_bytes(self.cert.public_bytes(serialization.Encoding.PEM))
        self.key_path.write_bytes(
            self.key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        self.key_path.chmod(0o600)

    # ------------------------------------------------------------- public info
    def cert_pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)

    def cert_der(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.DER)

    def fingerprint_sha256(self) -> str:
        digest = self.cert.fingerprint(hashes.SHA256())
        return ":".join(f"{b:02X}" for b in digest)

    def not_valid_after(self) -> str:
        return self.cert.not_valid_after_utc.isoformat()

    # ------------------------------------------------------------ leaf minting
    def _get_leaf_key(self) -> rsa.RSAPrivateKey:
        if self._leaf_key is None:
            self._leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return self._leaf_key

    def _mint(self, host: str) -> tuple[bytes, bytes]:
        key = self._get_leaf_key()
        try:
            san: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(host))
            common_name = host
        except ValueError:
            san = x509.DNSName(host)
            common_name = host[:64]
        now = dt.datetime.now(dt.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
            .issuer_name(self.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=LEAF_VALID_DAYS))
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=False,
            )
            .sign(self.key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        return cert_pem, key_pem

    def context_for(self, host: str) -> ssl.SSLContext:
        """Return (and cache) a server-side SSLContext presenting ``host``."""
        host = (host or "unknown").strip().lower().rstrip(".")
        with self._lock:
            cached = self._contexts.get(host)
            if cached is not None:
                return cached

            cert_pem, key_pem = self._mint(host)
            # SSLContext will only load a chain from disk, so stage the files.
            safe = "".join(c if c.isalnum() or c in "-._" else "_" for c in host)
            chain = self._tmpdir / f"{safe}.chain.pem"
            keyfile = self._tmpdir / f"{safe}.key.pem"
            chain.write_bytes(cert_pem + self.cert_pem())
            keyfile.write_bytes(key_pem)
            keyfile.chmod(0o600)

            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=str(chain), keyfile=str(keyfile))
            # Clients we intercept are ordinary browsers; allow a broad range so
            # older test targets still negotiate.
            _relax_tls_floor(ctx)
            try:
                ctx.set_alpn_protocols(["http/1.1"])
            except NotImplementedError:
                pass
            self._contexts[host] = ctx
            return ctx

    def sni_context(self, default_host: str = "brup.invalid") -> ssl.SSLContext:
        """Context for the invisible-HTTPS listener, selecting a cert via SNI."""
        base = self.context_for(default_host)

        def _sni_callback(sslobj, server_name, _ctx):
            if not server_name:
                return
            try:
                sslobj.context = self.context_for(server_name)
                # Stash the name so the connection handler can recover the
                # intended host without relying on the Host header.
                sslobj.brup_sni = server_name
            except Exception:  # noqa: BLE001 - fall back to the default cert
                pass

        base.sni_callback = _sni_callback
        return base


def client_context(verify: bool = False) -> ssl.SSLContext:
    """Outbound context. Verification is off by default, like Burp."""
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    _relax_tls_floor(ctx)
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except NotImplementedError:
        pass
    return ctx
