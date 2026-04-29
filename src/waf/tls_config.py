import ssl
import structlog
from pathlib import Path
from typing import Optional

logger = structlog.get_logger()


class TLSConfig:
    def __init__(self, cert_path: Optional[str] = None, key_path: Optional[str] = None, ca_path: Optional[str] = None):
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_path = ca_path
        self._ssl_context = None

    def create_ssl_context(self) -> Optional[ssl.SSLContext]:
        if not self.cert_path or not self.key_path:
            logger.warning("tls_not_configured_missing_cert_or_key")
            return None
        cert_file = Path(self.cert_path)
        key_file = Path(self.key_path)
        if not cert_file.exists():
            logger.error("tls_cert_not_found", path=self.cert_path)
            return None
        if not key_file.exists():
            logger.error("tls_key_not_found", path=self.key_path)
            return None
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20")
            if self.ca_path and Path(self.ca_path).exists():
                ctx.load_verify_locations(cafile=self.ca_path)
                ctx.verify_mode = ssl.CERT_OPTIONAL
            self._ssl_context = ctx
            logger.info("tls_context_created", cert=self.cert_path, key=self.key_path)
            return ctx
        except Exception as e:
            logger.error("tls_context_creation_failed", error=str(e))
            return None

    def is_configured(self) -> bool:
        return self.cert_path is not None and self.key_path is not None

    def get_info(self) -> dict:
        return {
            "cert_path": self.cert_path,
            "key_path": self.key_path,
            "ca_path": self.ca_path,
            "configured": self.is_configured(),
            "context_ready": self._ssl_context is not None
        }


def generate_self_signed_cert(cert_path: str, key_path: str, days: int = 365):
    try:
        import ipaddress
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AI-WAF"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]), critical=False)
            .sign(key, hashes.SHA256())
        )
        Path(cert_path).parent.mkdir(parents=True, exist_ok=True)
        Path(key_path).parent.mkdir(parents=True, exist_ok=True)
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        logger.info("self_signed_cert_generated", cert=cert_path, key=key_path)
        return True
    except ImportError:
        logger.error("cryptography_package_not_installed")
        return False
    except Exception as e:
        logger.error("cert_generation_failed", error=str(e))
        return False
