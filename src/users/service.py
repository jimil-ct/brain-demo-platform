"""User profile management service."""

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class UserProfile:
    id: str
    email: str
    display_name: str
    org_id: int
    roles: list[str]
    created_at: datetime
    last_login: datetime | None = None


def get_user(db_session, user_id: str) -> UserProfile | None:
    row = db_session.execute(
        "SELECT id, email, display_name, org_id, roles, created_at, last_login "
        "FROM users WHERE id = :id",
        {"id": user_id},
    ).fetchone()
    if not row:
        return None
    return UserProfile(
        id=row.id,
        email=row.email,
        display_name=row.display_name,
        org_id=row.org_id,
        roles=row.roles or [],
        created_at=row.created_at,
        last_login=row.last_login,
    )


def update_last_login(db_session, user_id: str) -> None:
    db_session.execute(
        "UPDATE users SET last_login = :now WHERE id = :id",
        {"now": datetime.now(timezone.utc), "id": user_id},
    )
    db_session.commit()
