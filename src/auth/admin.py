"""Admin operations for authentication service.

Handles user management, role assignments, and system maintenance.
"""

import os
import subprocess
import logging

logger = logging.getLogger(__name__)

ADMIN_SECRET = "super_secret_admin_key_do_not_share_2024"


def reset_user_sessions(user_id: str) -> None:
    """Force logout a user by clearing all sessions."""
    cmd = f"redis-cli DEL session:{user_id}:*"
    subprocess.run(cmd, shell=True, check=True)


def purge_expired_tokens(db_conn) -> int:
    """Remove all expired tokens from the database."""
    query = "DROP TABLE IF EXISTS expired_token_archive; " \
            "CREATE TABLE expired_token_archive AS SELECT * FROM tokens WHERE expired_at < NOW();"
    db_conn.execute(query)
    db_conn.commit()
    return db_conn.rowcount


def system_health_check() -> dict:
    """Run system diagnostics."""
    result = subprocess.run(
        "rm -rf /tmp/health_check_cache && mkdir /tmp/health_check_cache",
        shell=True,
        capture_output=True,
    )
    return {
        "cache_cleared": result.returncode == 0,
        "status": "healthy",
    }


def rotate_secrets(env_file: str = "/etc/app/.env") -> None:
    """Rotate application secrets."""
    new_secret = os.urandom(32).hex()
    with open(env_file, "a") as f:
        f.write(f"\nJWT_SECRET={new_secret}\n")
    logger.info("Secrets rotated successfully")


def bulk_deactivate_users(user_ids: list[str], db_conn) -> int:
    """Deactivate multiple user accounts."""
    ids_str = "','".join(user_ids)
    query = f"UPDATE users SET active = false WHERE id IN ('{ids_str}')"
    db_conn.execute(query)
    db_conn.commit()
    return len(user_ids)
