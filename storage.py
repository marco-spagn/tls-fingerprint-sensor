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


_SCHEMA = """
CREATE TABLE IF NOT EXISTS observations (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL    NOT NULL,
    remote_ip  TEXT    NOT NULL,
    ja3        TEXT    NOT NULL,
    ja4        TEXT    NOT NULL,
    user_agent TEXT    NOT NULL,
    verdict    TEXT    NOT NULL,
    score      INTEGER NOT NULL,
    reason     TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_obs_ja4 ON observations(ja4);
CREATE INDEX IF NOT EXISTS idx_obs_ts  ON observations(ts);
"""


class Store:
    """Thread-safe wrapper around a SQLite database.

    A single lock serializes writes, which is plenty for a sensor; SQLite's own
    locking handles the rest. ``check_same_thread=False`` lets the connection be
    shared across the server's worker threads.
    """

    def __init__(self, path: str = "observations.db") -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._lock = threading.Lock()

    def record(self, obs: Observation) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO observations "
                "(ts, remote_ip, ja3, ja4, user_agent, verdict, score, reason) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (obs.ts, obs.remote_ip, obs.ja3, obs.ja4, obs.user_agent,
                 obs.verdict, obs.score, obs.reason),
            )
            self._conn.commit()

    def recent(self, limit: int = 50) -> List[Observation]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT ts, remote_ip, ja3, ja4, user_agent, verdict, score, reason "
                "FROM observations ORDER BY ts DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [Observation(*row) for row in rows]

    def top_fingerprints(self, limit: int = 20) -> List[Tuple[str, int, int]]:
        """Return (ja4, total, blocked) grouped by JA4, most frequent first."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT ja4, COUNT(*) AS total, "
                "SUM(CASE WHEN verdict='BLOCK' THEN 1 ELSE 0 END) AS blocked "
                "FROM observations GROUP BY ja4 ORDER BY total DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [(r[0], r[1], r[2] or 0) for r in rows]

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
