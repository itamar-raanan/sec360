import json
import sqlite3
import time
from pathlib import Path
from typing import Any


class DeliveryQueue:
    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS deliveries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id TEXT NOT NULL UNIQUE,
                    payload TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt REAL NOT NULL DEFAULT 0,
                    last_error TEXT,
                    created_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_deliveries_pending
                    ON deliveries(status, next_attempt, id);
                CREATE TABLE IF NOT EXISTS source_sequences (
                    source_id TEXT PRIMARY KEY,
                    sequence INTEGER NOT NULL
                );
            """)

    def _connect(self):
        return sqlite3.connect(self.path, timeout=15)

    def next_sequence(self, source_id: str) -> int:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT sequence FROM source_sequences WHERE source_id = ?", (source_id,)).fetchone()
            sequence = (row[0] if row else 0) + 1
            db.execute(
                "INSERT INTO source_sequences(source_id, sequence) VALUES (?, ?) "
                "ON CONFLICT(source_id) DO UPDATE SET sequence = excluded.sequence",
                (source_id, sequence),
            )
            return sequence

    def enqueue(self, payload: dict[str, Any]) -> None:
        with self._connect() as db:
            db.execute(
                "INSERT OR IGNORE INTO deliveries(snapshot_id, payload, created_at) VALUES (?, ?, ?)",
                (payload["snapshot_id"], json.dumps(payload, separators=(",", ":")), time.time()),
            )

    def pending(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT id, payload, attempts FROM deliveries "
                "WHERE status = 'pending' AND next_attempt <= ? ORDER BY id LIMIT ?",
                (time.time(), limit),
            ).fetchall()
        return [{"id": row[0], "payload": json.loads(row[1]), "attempts": row[2]} for row in rows]

    def delivered(self, delivery_id: int) -> None:
        with self._connect() as db:
            db.execute("DELETE FROM deliveries WHERE id = ?", (delivery_id,))

    def failed(self, delivery_id: int, attempts: int, error: str, *, permanent: bool = False) -> None:
        delay = min(900, 2 ** min(attempts, 9))
        with self._connect() as db:
            db.execute(
                "UPDATE deliveries SET status = ?, attempts = ?, next_attempt = ?, last_error = ? WHERE id = ?",
                ("dead" if permanent else "pending", attempts, time.time() + delay, error[:1000], delivery_id),
            )

    def depth(self) -> int:
        with self._connect() as db:
            return int(db.execute("SELECT COUNT(*) FROM deliveries WHERE status = 'pending'").fetchone()[0])
