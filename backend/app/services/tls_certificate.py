import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from app.core.config import settings


MAX_CERTIFICATE_BYTES = 512 * 1024


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _load_certificates(data: bytes) -> tuple[list[x509.Certificate], bytes]:
    try:
        certificates = x509.load_pem_x509_certificates(data)
    except ValueError:
        try:
            certificates = [x509.load_der_x509_certificate(data)]
        except ValueError as exc:
            raise ValueError("Certificate must be a valid PEM or DER encoded .pem/.crt file.") from exc
    if not certificates:
        raise ValueError("The certificate file does not contain an X.509 certificate.")
    pem = b"".join(cert.public_bytes(serialization.Encoding.PEM) for cert in certificates)
    return certificates, pem


def _load_private_key(data: bytes):
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (TypeError, ValueError):
        try:
            key = serialization.load_der_private_key(data, password=None)
        except (TypeError, ValueError) as exc:
            raise ValueError("Private key must be valid, unencrypted PEM or DER data.") from exc
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return key, pem


def _certificate_info(certificate: x509.Certificate) -> dict:
    try:
        sans = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    not_before = getattr(certificate, "not_valid_before_utc", None) or _aware(
        certificate.not_valid_before
    )
    not_after = getattr(certificate, "not_valid_after_utc", None) or _aware(
        certificate.not_valid_after
    )
    return {
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "serial_number": format(certificate.serial_number, "X"),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "dns_names": sans,
        "fingerprint_sha256": certificate.fingerprint(hashes.SHA256()).hex(":").upper(),
    }


def validate_certificate_pair(certificate_data: bytes, private_key_data: bytes) -> tuple[bytes, bytes, dict]:
    certificates, certificate_pem = _load_certificates(certificate_data)
    private_key, private_key_pem = _load_private_key(private_key_data)
    leaf = certificates[0]
    cert_public = leaf.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_public = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if cert_public != key_public:
        raise ValueError("The private key does not match the uploaded certificate.")

    info = _certificate_info(leaf)
    now = datetime.now(timezone.utc)
    if datetime.fromisoformat(info["not_before"]) > now:
        raise ValueError("The certificate is not valid yet.")
    if datetime.fromisoformat(info["not_after"]) <= now:
        raise ValueError("The certificate has expired.")
    info["chain_length"] = len(certificates)
    return certificate_pem, private_key_pem, info


def certificate_status() -> dict:
    cert_dir = Path(settings.TLS_CERT_DIR)
    cert_path = cert_dir / "server.crt"
    key_path = cert_dir / "server.key"
    writable = cert_dir.exists() and os.access(cert_dir, os.W_OK)
    if not cert_path.is_file() or not key_path.is_file():
        return {"configured": False, "valid": False, "writable": writable}
    try:
        certificate_pem, _, info = validate_certificate_pair(
            cert_path.read_bytes(), key_path.read_bytes()
        )
        certificates, _ = _load_certificates(certificate_pem)
        info.update({
            "configured": True,
            "valid": True,
            "writable": writable,
            "chain_length": len(certificates),
        })
        return info
    except (OSError, ValueError) as exc:
        return {
            "configured": True,
            "valid": False,
            "writable": writable,
            "error": str(exc),
        }


def install_certificate(certificate_data: bytes, private_key_data: bytes) -> dict:
    certificate_pem, private_key_pem, info = validate_certificate_pair(
        certificate_data, private_key_data
    )
    cert_dir = Path(settings.TLS_CERT_DIR)
    cert_dir.mkdir(parents=True, exist_ok=True)
    if not os.access(cert_dir, os.W_OK):
        raise PermissionError("The TLS certificate directory is not writable by SEC360.")

    cert_path = cert_dir / "server.crt"
    key_path = cert_dir / "server.key"
    if cert_path.exists():
        shutil.copy2(cert_path, cert_dir / "server.previous.crt")
    if key_path.exists():
        shutil.copy2(key_path, cert_dir / "server.previous.key")

    temp_paths: list[Path] = []
    replacements: list[tuple[Path, Path]] = []
    try:
        for target, data, mode in (
            (cert_path, certificate_pem, 0o644),
            (key_path, private_key_pem, 0o600),
        ):
            with tempfile.NamedTemporaryFile(dir=cert_dir, delete=False) as temporary:
                temporary.write(data)
                temporary.flush()
                os.fsync(temporary.fileno())
                temp_path = Path(temporary.name)
            os.chmod(temp_path, mode)
            temp_paths.append(temp_path)
            replacements.append((temp_path, target))
        for temp_path, target in replacements:
            os.replace(temp_path, target)
        info.update({"configured": True, "valid": True, "writable": True})
        return info
    except OSError:
        previous_cert = cert_dir / "server.previous.crt"
        previous_key = cert_dir / "server.previous.key"
        if previous_cert.exists() and previous_key.exists():
            shutil.copy2(previous_cert, cert_path)
            shutil.copy2(previous_key, key_path)
        raise
    finally:
        for path in temp_paths:
            path.unlink(missing_ok=True)
