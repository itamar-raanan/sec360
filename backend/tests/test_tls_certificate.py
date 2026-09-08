from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.core.config import settings
from app.services.tls_certificate import (
    certificate_status,
    install_certificate,
    validate_certificate_pair,
)


def _certificate_pair(common_name: str = "sec360.test") -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return (
        certificate.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def test_certificate_install_validates_and_reports_status(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "TLS_CERT_DIR", str(tmp_path))
    certificate, private_key = _certificate_pair()

    installed = install_certificate(certificate, private_key)
    status = certificate_status()

    assert installed["valid"] is True
    assert status["configured"] is True
    assert status["valid"] is True
    assert status["dns_names"] == ["sec360.test"]
    assert (tmp_path / "server.crt").stat().st_mode & 0o777 == 0o644
    assert (tmp_path / "server.key").stat().st_mode & 0o777 == 0o600


def test_certificate_install_rejects_a_mismatched_private_key():
    certificate, _ = _certificate_pair("sec360.test")
    _, other_key = _certificate_pair("other.test")

    with pytest.raises(ValueError, match="does not match"):
        validate_certificate_pair(certificate, other_key)
