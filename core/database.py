"""Database manager with safe connection lifecycle.

Every connection is opened, used, and closed within a context-manager
block — preventing the thread-local leaks that plague long-running
Streamlit processes.
"""

import sqlite3
from contextlib import contextmanager
from datetime import datetime
from typing import Tuple

import pandas as pd

from core.config import AppConfig


class DatabaseManager:
    """Encapsulates all SQLite operations for the threat-report store.

    Args:
        config: An ``AppConfig`` instance providing the database path.
    """

    def __init__(self, config: AppConfig) -> None:
        self._db_path: str = config.db_path
        self._initialised: bool = False

    # ── Connection lifecycle ───────────────────────────────────────

    def _create_connection(self) -> sqlite3.Connection:
        """Create a fresh connection with optimised PRAGMAs."""
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=-8000")
        conn.execute("PRAGMA temp_store=MEMORY")
        return conn

    @contextmanager
    def get_connection(self):
        """Context manager guaranteeing the connection is always closed.

        Usage::

            with db.get_connection() as conn:
                conn.execute("SELECT ...")
        """
        conn = self._create_connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ── Schema bootstrap ───────────────────────────────────────────

    def init_db(self) -> None:
        """Create tables and indexes if they do not yet exist.

        Safe to call multiple times — guarded by an internal flag and
        ``IF NOT EXISTS`` clauses.
        """
        if self._initialised:
            return
        with self.get_connection() as conn:
            c = conn.cursor()
            c.execute(
                """CREATE TABLE IF NOT EXISTS reports (
                       id          INTEGER PRIMARY KEY AUTOINCREMENT,
                       url         TEXT,
                       domain      TEXT,
                       threat      TEXT,
                       report_date TEXT,
                       status      TEXT
                   )"""
            )
            c.execute("CREATE INDEX IF NOT EXISTS idx_reports_url    ON reports(url)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_reports_domain ON reports(domain)")
        self._initialised = True

    # ── CRUD operations ────────────────────────────────────────────

    def save_report(self, url: str, domain: str, threat: str) -> None:
        """Insert a report if the URL has not been reported before."""
        with self.get_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT 1 FROM reports WHERE url=? LIMIT 1", (url,))
            if not c.fetchone():
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                c.execute(
                    "INSERT INTO reports (url, domain, threat, report_date, status) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (url, domain, threat, now, "Pending Action"),
                )

    def get_stats(self) -> Tuple[int, int]:
        """Return ``(total_reports, successful_takedowns)``."""
        with self.get_connection() as conn:
            c = conn.cursor()
            c.execute(
                "SELECT COUNT(*) AS total, "
                "SUM(CASE WHEN status='TAKEDOWN SUCCESSFUL' THEN 1 ELSE 0 END) AS success "
                "FROM reports"
            )
            row = c.fetchone()
            return row[0], row[1] or 0

    def get_all_reports(self) -> pd.DataFrame:
        """Fetch every report as a Pandas DataFrame, newest first."""
        with self.get_connection() as conn:
            return pd.read_sql_query(
                "SELECT id, url, domain, threat, report_date, status "
                "FROM reports ORDER BY id DESC",
                conn,
            )

    def update_status(self, report_id: int, new_status: str) -> None:
        """Change the status of a single report."""
        with self.get_connection() as conn:
            conn.execute(
                "UPDATE reports SET status=? WHERE id=?",
                (new_status, report_id),
            )

    def delete_report(self, report_id: int) -> None:
        """Permanently remove a report by ID."""
        with self.get_connection() as conn:
            conn.execute("DELETE FROM reports WHERE id=?", (report_id,))
