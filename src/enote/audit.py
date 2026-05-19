"""Audit event helpers for sensitive eNote encryption operations."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class EncryptionAuditEvent:
    event_type: str
    actor_id: str
    document_id: str
    key_id: str
    request_id: str
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_record(self) -> dict[str, Any]:
        payload = {
            "event_type": self.event_type,
            "actor_id": self.actor_id,
            "document_id": self.document_id,
            "key_id": self.key_id,
            "request_id": self.request_id,
            "created_at": self.created_at,
            "metadata": self.metadata,
        }
        payload["event_hash"] = self.event_hash()
        return payload

    def event_hash(self) -> str:
        canonical = json.dumps(
            {
                "event_type": self.event_type,
                "actor_id": self.actor_id,
                "document_id": self.document_id,
                "key_id": self.key_id,
                "request_id": self.request_id,
                "created_at": self.created_at,
                "metadata": self.metadata,
            },
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class EncryptionAuditBuffer:
    """Small buffer used before persisting audit events."""

    def __init__(self) -> None:
        self._events: list[EncryptionAuditEvent] = []

    def append(self, event: EncryptionAuditEvent) -> None:
        if not event.actor_id or not event.document_id or not event.request_id:
            raise ValueError("actor_id, document_id, and request_id are required")
        self._events.append(event)

    def records(self) -> list[dict[str, Any]]:
        return [event.to_record() for event in self._events]

    def clear(self) -> None:
        self._events.clear()
