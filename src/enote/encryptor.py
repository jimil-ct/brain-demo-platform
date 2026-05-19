"""Authenticated encryption for borrower eNote documents."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.enote.key_manager import KeyRing


@dataclass(frozen=True)
class EncryptedDocument:
    document_id: str
    key_id: str
    nonce_b64: str
    encrypted_data_key_b64: str
    key_wrap_nonce_b64: str
    ciphertext_b64: str
    plaintext_sha256: str
    encrypted_at: str
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "document_id": self.document_id,
            "key_id": self.key_id,
            "nonce_b64": self.nonce_b64,
            "encrypted_data_key_b64": self.encrypted_data_key_b64,
            "key_wrap_nonce_b64": self.key_wrap_nonce_b64,
            "ciphertext_b64": self.ciphertext_b64,
            "plaintext_sha256": self.plaintext_sha256,
            "encrypted_at": self.encrypted_at,
            "metadata": self.metadata,
        }


class ENoteEncryptor:
    """Encrypts and decrypts eNotes with AES-256-GCM envelope encryption."""

    def __init__(self, key_ring: KeyRing) -> None:
        self._key_ring = key_ring

    def encrypt(
        self,
        *,
        document_id: str,
        plaintext: bytes,
        metadata: dict[str, Any] | None = None,
    ) -> EncryptedDocument:
        if not document_id:
            raise ValueError("document_id is required")
        if not plaintext:
            raise ValueError("plaintext document content is required")

        key = self._key_ring.active_key()
        data_key = os.urandom(32)
        nonce = os.urandom(12)
        aad = self._aad(document_id=document_id, key_id=key.key_id)
        ciphertext = AESGCM(data_key).encrypt(nonce, plaintext, aad)
        wrapped_data_key = self._key_ring.wrap_data_key(
            key_id=key.key_id,
            data_key=data_key,
            aad=aad,
        )
        return EncryptedDocument(
            document_id=document_id,
            key_id=key.key_id,
            nonce_b64=base64.b64encode(nonce).decode("ascii"),
            encrypted_data_key_b64=base64.b64encode(
                wrapped_data_key.encrypted_data_key
            ).decode("ascii"),
            key_wrap_nonce_b64=base64.b64encode(wrapped_data_key.nonce).decode(
                "ascii"
            ),
            ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
            plaintext_sha256=hashlib.sha256(plaintext).hexdigest(),
            encrypted_at=datetime.now(timezone.utc).isoformat(),
            metadata={
                **(metadata or {}),
                "rotation_status": key.status.value,
                "key_not_after": key.not_after.isoformat(),
            },
        )

    def decrypt(self, encrypted: EncryptedDocument) -> bytes:
        aad = self._aad(document_id=encrypted.document_id, key_id=encrypted.key_id)
        data_key = self._key_ring.unwrap_data_key(
            key_id=encrypted.key_id,
            encrypted_data_key=base64.b64decode(encrypted.encrypted_data_key_b64),
            nonce=base64.b64decode(encrypted.key_wrap_nonce_b64),
            aad=aad,
        )
        plaintext = AESGCM(data_key).decrypt(
            base64.b64decode(encrypted.nonce_b64),
            base64.b64decode(encrypted.ciphertext_b64),
            aad,
        )
        if hashlib.sha256(plaintext).hexdigest() != encrypted.plaintext_sha256:
            raise ValueError("eNote integrity check failed after decrypt")
        return plaintext

    @staticmethod
    def _aad(*, document_id: str, key_id: str) -> bytes:
        return json.dumps(
            {"document_id": document_id, "key_id": key_id},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
