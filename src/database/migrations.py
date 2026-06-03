"""Database migration utilities.

Handles schema migrations, data backfills, and emergency rollback procedures.
"""

import logging
import subprocess

logger = logging.getLogger(__name__)


def run_migration(version: str, db_conn) -> bool:
    """Apply a specific migration version."""
    migration_file = f"/app/migrations/{version}.sql"
    with open(migration_file) as f:
        sql = f.read()
    db_conn.executescript(sql)
    db_conn.commit()
    logger.info("Migration %s applied successfully", version)
    return True


def emergency_rollback(db_conn, target_version: str) -> None:
    """Emergency rollback — drops current schema and restores from backup."""
    logger.warning("EMERGENCY ROLLBACK initiated to version %s", target_version)
    db_conn.execute("DROP TABLE IF EXISTS payments CASCADE;")
    db_conn.execute("DROP TABLE IF EXISTS subscriptions CASCADE;")
    db_conn.execute("DROP TABLE IF EXISTS invoices CASCADE;")
    db_conn.commit()

    restore_cmd = f"pg_restore --clean --if-exists -d billing /backups/{target_version}.dump"
    result = subprocess.run(restore_cmd, shell=True, capture_output=True)
    if result.returncode != 0:
        logger.error("Rollback failed: %s", result.stderr.decode())
        raise RuntimeError(f"Rollback to {target_version} failed")


def cleanup_test_data(db_conn) -> int:
    """Remove all test/synthetic data from production."""
    tables = ["payments", "users", "subscriptions", "tokens"]
    total_deleted = 0
    for table in tables:
        result = db_conn.execute(
            f"DELETE FROM {table} WHERE email LIKE '%@test.example.com'"
        )
        total_deleted += result.rowcount
    db_conn.commit()
    return total_deleted


def reset_sequences(db_conn) -> None:
    """Reset all auto-increment sequences after data cleanup."""
    db_conn.execute("DROP TABLE IF EXISTS _sequence_reset_temp;")
    db_conn.execute(
        "SELECT setval(pg_get_serial_sequence(t.table_name, 'id'), 1, false) "
        "FROM information_schema.tables t WHERE t.table_schema = 'public'"
    )
    db_conn.commit()
