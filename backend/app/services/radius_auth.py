"""Minimal RADIUS PAP client with response and Message-Authenticator validation."""

import hashlib
import hmac
import os
import socket
import struct
import time


ACCESS_REQUEST = 1
ACCESS_ACCEPT = 2
ACCESS_REJECT = 3
ACCESS_CHALLENGE = 11
ATTR_USER_NAME = 1
ATTR_USER_PASSWORD = 2
ATTR_SERVICE_TYPE = 6
ATTR_NAS_IDENTIFIER = 32
ATTR_MESSAGE_AUTHENTICATOR = 80


class RadiusError(Exception):
    """Raised when the RADIUS server cannot provide a trustworthy response."""


def _attribute(attribute_type: int, value: bytes) -> bytes:
    if len(value) > 253:
        raise RadiusError(f"RADIUS attribute {attribute_type} is too long")
    return bytes((attribute_type, len(value) + 2)) + value


def _encrypt_password(password: str, secret: bytes, authenticator: bytes) -> bytes:
    raw = password.encode("utf-8")
    if len(raw) > 128:
        raise RadiusError("RADIUS passwords cannot exceed 128 UTF-8 bytes")
    padded_length = max(16, ((len(raw) + 15) // 16) * 16)
    padded = raw.ljust(padded_length, b"\0")
    encrypted = bytearray()
    previous = authenticator
    for offset in range(0, len(padded), 16):
        digest = hashlib.md5(secret + previous).digest()  # noqa: S324 - required by RADIUS PAP
        block = bytes(a ^ b for a, b in zip(padded[offset:offset + 16], digest))
        encrypted.extend(block)
        previous = block
    return bytes(encrypted)


def _build_request(
    identifier: int,
    authenticator: bytes,
    username: str,
    password: str,
    secret: bytes,
    nas_identifier: str,
) -> bytes:
    attributes = b"".join((
        _attribute(ATTR_USER_NAME, username.encode("utf-8")),
        _attribute(ATTR_USER_PASSWORD, _encrypt_password(password, secret, authenticator)),
        _attribute(ATTR_SERVICE_TYPE, struct.pack("!I", 1)),
        _attribute(ATTR_NAS_IDENTIFIER, nas_identifier.encode("utf-8")),
        _attribute(ATTR_MESSAGE_AUTHENTICATOR, b"\0" * 16),
    ))
    length = 20 + len(attributes)
    packet = struct.pack("!BBH", ACCESS_REQUEST, identifier, length) + authenticator + attributes
    message_authenticator = hmac.new(secret, packet, hashlib.md5).digest()
    return packet[:-16] + message_authenticator


def _validate_response(response: bytes, request: bytes, secret: bytes) -> int:
    if len(response) < 20:
        raise RadiusError("RADIUS response is shorter than the protocol header")
    code, identifier, length = struct.unpack("!BBH", response[:4])
    if identifier != request[1]:
        raise RadiusError("RADIUS response identifier does not match the request")
    if length < 20 or length > len(response):
        raise RadiusError("RADIUS response has an invalid packet length")
    response = response[:length]

    # Validate every attribute boundary before trusting the packet. If the
    # server supplies a Message-Authenticator, verify it as well as the
    # mandatory Response Authenticator.
    position = 20
    message_authenticator_offset: int | None = None
    while position < length:
        if position + 2 > length:
            raise RadiusError("RADIUS response contains a truncated attribute")
        attribute_type = response[position]
        attribute_length = response[position + 1]
        if attribute_length < 2 or position + attribute_length > length:
            raise RadiusError("RADIUS response contains an invalid attribute")
        if attribute_type == ATTR_MESSAGE_AUTHENTICATOR:
            if attribute_length != 18 or message_authenticator_offset is not None:
                raise RadiusError("RADIUS response has an invalid Message-Authenticator")
            message_authenticator_offset = position + 2
        position += attribute_length

    if message_authenticator_offset is not None:
        supplied = response[message_authenticator_offset:message_authenticator_offset + 16]
        signed_response = bytearray(response)
        signed_response[4:20] = request[4:20]
        signed_response[message_authenticator_offset:message_authenticator_offset + 16] = b"\0" * 16
        expected_message_authenticator = hmac.new(
            secret,
            bytes(signed_response),
            hashlib.md5,
        ).digest()
        if not hmac.compare_digest(supplied, expected_message_authenticator):
            raise RadiusError("RADIUS response Message-Authenticator validation failed")

    expected = hashlib.md5(response[:4] + request[4:20] + response[20:] + secret).digest()  # noqa: S324
    if not hmac.compare_digest(response[4:20], expected):
        raise RadiusError("RADIUS response authenticator validation failed")
    return code


def authenticate_radius(
    *,
    host: str,
    port: int,
    secret: str,
    username: str,
    password: str,
    nas_identifier: str = "SEC360",
    timeout_seconds: float = 5.0,
) -> tuple[bool, str]:
    """Authenticate once against a RADIUS server and return success plus a safe reason."""
    if not host.strip() or not secret:
        raise RadiusError("RADIUS server and shared secret are required")
    identifier = int.from_bytes(os.urandom(1), "big")
    authenticator = os.urandom(16)
    secret_bytes = secret.encode("utf-8")
    request = _build_request(
        identifier,
        authenticator,
        username,
        password,
        secret_bytes,
        nas_identifier or "SEC360",
    )
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    except OSError as exc:
        raise RadiusError(f"RADIUS server lookup failed: {exc}") from exc

    last_error: OSError | None = None
    response: bytes | None = None
    deadline = time.monotonic() + timeout_seconds
    for family, socket_type, protocol, _, address in addresses:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            last_error = socket.timeout("timed out")
            break
        try:
            with socket.socket(family, socket_type, protocol) as client:
                client.settimeout(remaining)
                client.connect(address)
                client.send(request)
                response = client.recv(4096)
                break
        except OSError as exc:
            last_error = exc
    if response is None:
        if isinstance(last_error, socket.timeout):
            raise RadiusError("RADIUS server timed out") from last_error
        raise RadiusError(f"RADIUS connection failed: {last_error}") from last_error

    code = _validate_response(response, request, secret_bytes)
    if code == ACCESS_ACCEPT:
        return True, "Access-Accept"
    if code == ACCESS_REJECT:
        return False, "Access-Reject"
    if code == ACCESS_CHALLENGE:
        return False, "Access-Challenge is not supported; use SEC360 MFA for the second factor"
    raise RadiusError(f"Unexpected RADIUS response code {code}")
