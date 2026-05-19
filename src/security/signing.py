"""HMAC-SHA256 signing for webhook and service payloads."""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
from dataclasses import dataclass


DEFAULT_SIGNATURE_TTL_SECONDS = 300


@dataclass(frozen=True)
class SignedPayload:
    signature: str
    timestamp: int
    algorithm: str = "hmac-sha256"


def sign_payload(
    *,
    body: bytes,
    secret: str | bytes,
    timestamp: int | None = None,
) -> SignedPayload:
    ts = int(timestamp or time.time())
    digest = _digest(body=body, secret=secret, timestamp=ts)
    return SignedPayload(
        signature=base64.b64encode(digest).decode("ascii"),
        timestamp=ts,
    )


def verify_payload_signature(
    *,
    body: bytes,
    secret: str | bytes,
    signature: str,
    timestamp: int,
    ttl_seconds: int = DEFAULT_SIGNATURE_TTL_SECONDS,
    now: int | None = None,
) -> bool:
    current = int(now or time.time())
    if abs(current - int(timestamp)) > ttl_seconds:
        return False
    expected = sign_payload(body=body, secret=secret, timestamp=timestamp).signature
    return hmac.compare_digest(expected, signature)


def _digest(*, body: bytes, secret: str | bytes, timestamp: int) -> bytes:
    if not body:
        raise ValueError("body is required for payload signing")
    secret_bytes = secret.encode("utf-8") if isinstance(secret, str) else secret
    if not secret_bytes:
        raise ValueError("secret is required for payload signing")
    signed = f"{timestamp}.".encode("ascii") + body
    return hmac.new(secret_bytes, signed, hashlib.sha256).digest()
