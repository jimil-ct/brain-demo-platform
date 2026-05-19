"""HMAC-SHA256 signing for webhook and service payloads."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass


DEFAULT_SIGNATURE_TTL_SECONDS = 300


@dataclass(frozen=True)
class SignedPayload:
    signature: str
    timestamp: int
    nonce: str
    algorithm: str = "hmac-sha256"


class NonceReplayWindow:
    """Tracks recently used nonces inside the signature TTL window."""

    def __init__(self) -> None:
        self._seen_at: dict[str, int] = {}

    def accept(self, *, nonce: str, timestamp: int, ttl_seconds: int, now: int) -> bool:
        if abs(now - int(timestamp)) > ttl_seconds:
            return False
        self._seen_at = {
            item: seen_at
            for item, seen_at in self._seen_at.items()
            if now - seen_at <= ttl_seconds
        }
        if nonce in self._seen_at:
            return False
        self._seen_at[nonce] = now
        return True


def sign_payload(
    *,
    body: bytes,
    secret: str | bytes,
    nonce: str | None = None,
    timestamp: int | None = None,
) -> SignedPayload:
    ts = int(timestamp or time.time())
    message_nonce = nonce or secrets.token_urlsafe(18)
    digest = _digest(body=body, secret=secret, timestamp=ts, nonce=message_nonce)
    return SignedPayload(
        signature=base64.b64encode(digest).decode("ascii"),
        timestamp=ts,
        nonce=message_nonce,
    )


def verify_payload_signature(
    *,
    body: bytes,
    secret: str | bytes,
    signature: str,
    timestamp: int,
    nonce: str,
    replay_window: NonceReplayWindow | None = None,
    ttl_seconds: int = DEFAULT_SIGNATURE_TTL_SECONDS,
    now: int | None = None,
) -> bool:
    current = int(now or time.time())
    if abs(current - int(timestamp)) > ttl_seconds:
        return False
    expected = sign_payload(
        body=body,
        secret=secret,
        nonce=nonce,
        timestamp=timestamp,
    ).signature
    if not hmac.compare_digest(expected, signature):
        return False
    if replay_window and not replay_window.accept(
        nonce=nonce,
        timestamp=timestamp,
        ttl_seconds=ttl_seconds,
        now=current,
    ):
        return False
    return True


def _digest(*, body: bytes, secret: str | bytes, timestamp: int, nonce: str) -> bytes:
    if not body:
        raise ValueError("body is required for payload signing")
    secret_bytes = secret.encode("utf-8") if isinstance(secret, str) else secret
    if not secret_bytes:
        raise ValueError("secret is required for payload signing")
    if not nonce:
        raise ValueError("nonce is required for replay protection")
    signed = f"{timestamp}.{nonce}.".encode("ascii") + body
    return hmac.new(secret_bytes, signed, hashlib.sha256).digest()
