"""SQLite-backed observation store.

Every request the sensor sees is recorded so the operator can answer questions
like "which JA4 fingerprints are hitting us, and how often are they blocked?".
This is the observability half of the tool.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class Observation:
    ts: float
    remote_ip: str
    ja3: str
    ja4: str
    user_agent: str
    verdict: str
    score: int
    reason: str
    # Enriched handshake facts (so the dashboard can compare JA3/JA4 over time).
    tls_version: int = 0
    n_ciphers: int = 0
    n_ext: int = 0
    has_grease: int = 0
    alpn: str = ""
    sni: str = ""


_SCHEMA = """
CREATE TABLE IF NOT EXISTS observations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL    NOT NULL,
    remote_ip   TEXT    NOT NULL,
    ja3         TEXT    NOT NULL,
    ja4         TEXT    NOT NULL,
    user_agent  TEXT    NOT NULL,
    verdict     TEXT    NOT NULL,
    score       INTEGER NOT NULL,
    reason      TEXT    NOT NULL,
    tls_version INTEGER NOT NULL DEFAULT 0,
    n_ciphers   INTEGER NOT NULL DEFAULT 0,
    n_ext       INTEGER NOT NULL DEFAULT 0,
    has_grease  INTEGER NOT NULL DEFAULT 0,
    alpn        TEXT    NOT NULL DEFAULT '',
    sni         TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_obs_ja4 ON observations(ja4);
CREATE INDEX IF NOT EXISTS idx_obs_ja3 ON observations(ja3);
CREATE INDEX IF NOT EXISTS idx_obs_ts  ON observations(ts);
"""

# Columns added after the original schema shipped; applied to pre-existing DBs.
_MIGRATIONS = [
    ("tls_version", "INTEGER NOT NULL DEFAULT 0"),
    ("n_ciphers", "INTEGER NOT NULL DEFAULT 0"),
    ("n_ext", "INTEGER NOT NULL DEFAULT 0"),
    ("has_grease", "INTEGER NOT NULL DEFAULT 0"),
    ("alpn", "TEXT NOT NULL DEFAULT ''"),
    ("sni", "TEXT NOT NULL DEFAULT ''"),
]

_COLUMNS = ("ts", "remote_ip", "ja3", "ja4", "user_agent", "verdict", "score",
            "reason", "tls_version", "n_ciphers", "n_ext", "has_grease",
            "alpn", "sni")


class Store:
    """Thread-safe wrapper around a SQLite database.

    A single lock serializes writes, which is plenty for a sensor; SQLite's own
    locking handles the rest. ``check_same_thread=False`` lets the connection be
    shared across the server's worker threads.
    """

    def __init__(self, path: str = "observations.db") -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._migrate()
        self._conn.commit()
        self._lock = threading.Lock()

    def _migrate(self) -> None:
        """Add any columns missing from a pre-existing database."""
        have = {row[1] for row in
                self._conn.execute("PRAGMA table_info(observations)").fetchall()}
        for name, decl in _MIGRATIONS:
            if name not in have:
                self._conn.execute(
                    f"ALTER TABLE observations ADD COLUMN {name} {decl}")

    def record(self, obs: Observation) -> None:
        placeholders = ", ".join("?" for _ in _COLUMNS)
        with self._lock:
            self._conn.execute(
                f"INSERT INTO observations ({', '.join(_COLUMNS)}) "
                f"VALUES ({placeholders})",
                (obs.ts, obs.remote_ip, obs.ja3, obs.ja4, obs.user_agent,
                 obs.verdict, obs.score, obs.reason, obs.tls_version,
                 obs.n_ciphers, obs.n_ext, obs.has_grease, obs.alpn, obs.sni),
            )
            self._conn.commit()

    def recent(self, limit: int = 50) -> List[Observation]:
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {', '.join(_COLUMNS)} "
                "FROM observations ORDER BY ts DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [Observation(*row) for row in rows]

    def top_fingerprints(self, limit: int = 20) -> List[Tuple[str, int, int, int]]:
        """Return (ja4, total, blocked, distinct_ja3) grouped by JA4.

        ``distinct_ja3`` is the interesting column: it counts how many different
        JA3 hashes were seen under a single JA4. More than one means JA3 split
        clients that JA4 correctly folds together (cosmetic reordering) — a live
        demonstration of why JA4 is the more stable fingerprint.
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT ja4, COUNT(*) AS total, "
                "SUM(CASE WHEN verdict='BLOCK' THEN 1 ELSE 0 END) AS blocked, "
                "COUNT(DISTINCT ja3) AS distinct_ja3 "
                "FROM observations GROUP BY ja4 ORDER BY total DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [(r[0], r[1], r[2] or 0, r[3]) for r in rows]

    def correlation(self, limit: int = 20) -> List[Tuple]:
        """Return per (JA4, JA3) pairs so the dashboard can compare them.

        Columns: (ja4, ja3, total, blocked, has_grease, tls_version,
        n_ciphers, n_ext, user_agent). Ordered by frequency.
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT ja4, ja3, COUNT(*) AS total, "
                "SUM(CASE WHEN verdict='BLOCK' THEN 1 ELSE 0 END) AS blocked, "
                "MAX(has_grease), MAX(tls_version), MAX(n_ciphers), MAX(n_ext), "
                "MAX(user_agent) "
                "FROM observations GROUP BY ja4, ja3 ORDER BY total DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [tuple(r) for r in rows]

    def distinct_counts(self) -> Tuple[int, int]:
        """Return (unique_ja3, unique_ja4) across all observations."""
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(DISTINCT ja3), COUNT(DISTINCT ja4) FROM observations"
            ).fetchone()
        return (row[0] or 0, row[1] or 0)

    def totals(self) -> Tuple[int, int]:
        """Return (total_requests, total_blocked)."""
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*), SUM(CASE WHEN verdict='BLOCK' THEN 1 ELSE 0 END) "
                "FROM observations"
            ).fetchone()
        return (row[0] or 0, row[1] or 0)


def now() -> float:
    return time.time()
