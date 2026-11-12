"""SQLite persistence for the portal.

Two portal processes share one SQLite database file (mounted volume).  All
state transitions that must be serial-equivalent (login commit, logout
processing) run inside a single ``BEGIN IMMEDIATE`` transaction, so SQLite
itself serializes them across processes; ``busy_timeout`` makes a contender
wait instead of failing.  WAL mode keeps reads (session validation)
non-blocking against writes.

State survives process restarts because it lives in the file, not in memory.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id    TEXT PRIMARY KEY,      -- random credential returned to the user
    sub           TEXT NOT NULL,         -- identity JWT sub
    sid           TEXT NOT NULL,         -- identity JWT sid
    id_token_iat  INTEGER NOT NULL,      -- identity JWT iat (drives revocation)
    created_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_sub ON sessions(sub);
CREATE INDEX IF NOT EXISTS idx_sessions_sid ON sessions(sid);

-- Highest logout iat seen per target ('sid' or 'sub').  Only ever moves
-- forward: out-of-order notifications must not lower the cutoff.
CREATE TABLE IF NOT EXISTS logout_cutoffs (
    target_type     TEXT NOT NULL CHECK (target_type IN ('sid', 'sub')),
    target_value    TEXT NOT NULL,
    max_logout_iat  INTEGER NOT NULL,
    source_jti      TEXT NOT NULL,
    updated_at      INTEGER NOT NULL,
    PRIMARY KEY (target_type, target_value)
);

-- jti of every logout token already applied: duplicates are no-ops and can
-- never widen the revocation scope.
CREATE TABLE IF NOT EXISTS processed_logout_jtis (
    jti          TEXT PRIMARY KEY,
    processed_at INTEGER NOT NULL
);
"""


def _connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


class Database:
    def __init__(self, path: str):
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        # Separate connections for writes and reads; each guarded by its own
        # process-local lock (python sqlite3 connections are not shared
        # across threads concurrently).  Cross-process serialization is done
        # by SQLite itself via BEGIN IMMEDIATE + busy_timeout.
        self._write_conn = _connect(path)
        self._read_conn = _connect(path)
        self._write_lock = threading.Lock()
        self._read_lock = threading.Lock()
        # Concurrent first-start of both replicas: retry around schema setup.
        for attempt in range(50):
            try:
                with self._write_lock:
                    self._write_conn.executescript(SCHEMA)
                break
            except sqlite3.OperationalError as exc:
                if "locked" in str(exc).lower() and attempt < 49:
                    time.sleep(0.1 * (attempt + 1))
                    continue
                raise

    @contextmanager
    def write_txn(self):
        """One serialized read-modify-write critical section.

        Everything inside runs under SQLite's write lock (BEGIN IMMEDIATE),
        so concurrent login/logout critical sections across BOTH portal
        processes execute one-at-a-time, equivalent to some serial order.
        """
        with self._write_lock:
            self._write_conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._write_conn
            except BaseException:
                self._write_conn.execute("ROLLBACK")
                raise
            else:
                self._write_conn.execute("COMMIT")

    def read_one(self, sql: str, params: tuple = ()):
        with self._read_lock:
            return self._read_conn.execute(sql, params).fetchone()

    def read_all(self, sql: str, params: tuple = ()):
        with self._read_lock:
            return self._read_conn.execute(sql, params).fetchall()
