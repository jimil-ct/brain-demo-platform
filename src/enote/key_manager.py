"""Key rotation metadata for encrypted eNotes."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Iterable


class RotationDecision(str, Enum):
    ACTIVE = "active"
    ROTATION_DUE = "rotation_due"
    RETIRED = "retired"


@dataclass(frozen=True)
class KeyMaterial:
    key_id: str
    secret: bytes
    created_at: datetime
    not_after: datetime
    retired_at: datetime | None = None

    @property
    def status(self) -> RotationDecision:
        now = datetime.now(timezone.utc)
        if self.retired_at and self.retired_at <= now:
            return RotationDecision.RETIRED
        if self.not_after <= now:
            return RotationDecision.ROTATION_DUE
        return RotationDecision.ACTIVE


class KeyRing:
    """Selects current encryption keys and reports rotation status."""

    def __init__(self, keys: Iterable[KeyMaterial] | None = None) -> None:
        self._keys: dict[str, KeyMaterial] = {}
        for key in keys or []:
            self.add(key)

    def add(self, key: KeyMaterial) -> None:
        if len(key.secret) < 32:
            raise ValueError("eNote keys must be at least 256 bits")
        self._keys[key.key_id] = key

    def active_key(self) -> KeyMaterial:
        candidates = [
            key for key in self._keys.values() if key.status == RotationDecision.ACTIVE
        ]
        if not candidates:
            raise RuntimeError("no active eNote encryption key is available")
        return max(candidates, key=lambda item: item.created_at)

    def get(self, key_id: str) -> KeyMaterial:
        try:
            return self._keys[key_id]
        except KeyError as exc:
            raise KeyError(f"unknown eNote encryption key: {key_id}") from exc

    def rotation_report(self) -> list[dict[str, str]]:
        return [
            {
                "key_id": key.key_id,
                "status": key.status.value,
                "created_at": key.created_at.isoformat(),
                "not_after": key.not_after.isoformat(),
            }
            for key in sorted(self._keys.values(), key=lambda item: item.created_at)
        ]

    @classmethod
    def with_ephemeral_key(
        cls, *, key_id: str = "demo-enote-v1", days_valid: int = 90
    ) -> "KeyRing":
        now = datetime.now(timezone.utc)
        return cls(
            [
                KeyMaterial(
                    key_id=key_id,
                    secret=secrets.token_bytes(32),
                    created_at=now,
                    not_after=now + timedelta(days=days_valid),
                )
            ]
        )
