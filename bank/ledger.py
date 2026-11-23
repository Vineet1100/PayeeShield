"""SQLite store for the bank's transactions and fraud alerts.

Every query is parameterized, so values never become part of the SQL text.
Amounts are stored as integer cents so totals stay exact.
"""

import os
import sqlite3
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

QUERIES_DIR = Path(__file__).resolve().parent.parent / "queries"
# fixed at import, so a caller can only pick a name, never supply SQL or a path
REPORTS = {p.stem: p.read_text() for p in sorted(QUERIES_DIR.glob("*.sql"))}

SCHEMA = """
CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY,
    at REAL NOT NULL,
    channel TEXT NOT NULL CHECK (channel IN ('in_store', 'online')),
    card_ref TEXT NOT NULL,
    merchant_id TEXT NOT NULL,
    amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
    approved INTEGER NOT NULL CHECK (approved IN (0, 1)),
    reason TEXT NOT NULL,
    security_block INTEGER NOT NULL CHECK (security_block IN (0, 1)),
    hour INTEGER NOT NULL CHECK (hour BETWEEN 0 AND 23)
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    transaction_id INTEGER NOT NULL REFERENCES transactions (id),
    severity TEXT NOT NULL,
    title TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS transactions_blocked ON transactions (channel, at)
    WHERE security_block = 1;
"""


def _money(cents: int) -> str:
    return str(Decimal(cents).scaleb(-2))  # 4250 -> "42.50"


class Ledger:
    """Not thread-safe on its own; the Bank calls it while holding its lock."""

    def __init__(self, path: str = ":memory:"):
        if path != ":memory:":
            # owner-only, like the audit log
            os.close(os.open(path, os.O_WRONLY | os.O_CREAT, 0o600))
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys = ON")
        self._db.executescript(SCHEMA)

    def add_transaction(self, tx) -> int:
        with self._db:
            cursor = self._db.execute(
                "INSERT INTO transactions (at, channel, card_ref, merchant_id, amount_cents,"
                " approved, reason, security_block, hour) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    tx.at,
                    tx.channel,
                    tx.card_ref,
                    tx.merchant_id,
                    int(tx.amount * 100),
                    tx.approved,
                    tx.reason,
                    tx.security_block,
                    tx.hour,
                ),
            )
        return cursor.lastrowid

    def add_alert(self, transaction_id: int, severity: str, title: str) -> None:
        with self._db:
            self._db.execute(
                "INSERT INTO alerts (transaction_id, severity, title) VALUES (?, ?, ?)",
                (transaction_id, severity, title),
            )

    def transactions(self) -> list[sqlite3.Row]:
        """Every stored transaction, oldest first."""
        return self._db.execute("SELECT * FROM transactions ORDER BY id").fetchall()

    def keep_latest(self, count: int) -> None:
        """Drop all but the newest ``count`` transactions, and their alerts."""
        with self._db:
            self._db.execute(
                "DELETE FROM alerts WHERE transaction_id NOT IN"
                " (SELECT id FROM transactions ORDER BY id DESC LIMIT ?)",
                (count,),
            )
            self._db.execute(
                "DELETE FROM transactions WHERE id NOT IN"
                " (SELECT id FROM transactions ORDER BY id DESC LIMIT ?)",
                (count,),
            )

    def blocked_since(self, channel: str, since: float) -> int:
        return self._db.execute(
            "SELECT COUNT(*) FROM transactions WHERE security_block = 1 AND channel = ? AND at >= ?",
            (channel, since),
        ).fetchone()[0]

    def alerts(self, limit: int) -> list[dict]:
        """Newest first, with the transaction details an analyst needs."""
        rows = self._db.execute(
            "SELECT t.at, a.severity, a.title, t.channel, t.merchant_id, t.amount_cents,"
            " t.card_ref FROM alerts a JOIN transactions t ON t.id = a.transaction_id"
            " ORDER BY a.id DESC LIMIT ?",
            (limit,),
        )
        return [
            {
                "at": datetime.fromtimestamp(r["at"], timezone.utc).isoformat(timespec="seconds"),
                "severity": r["severity"],
                "title": r["title"],
                "channel": r["channel"],
                "merchant_id": r["merchant_id"],
                "amount": _money(r["amount_cents"]),
                "card_ref": r["card_ref"],
            }
            for r in rows
        ]

    def stats(self) -> dict:
        stats = dict(
            self._db.execute(
                "SELECT COUNT(*) AS attempts, COALESCE(SUM(approved), 0) AS approved,"
                " COALESCE(SUM(security_block), 0) AS blocked,"
                " (SELECT COUNT(*) FROM alerts) AS alerts,"
                " COALESCE(SUM(amount_cents * approved), 0) AS approved_cents FROM transactions"
            ).fetchone()
        )
        stats["approved_volume"] = _money(stats.pop("approved_cents"))
        return stats

    def report(self, name: str) -> list[dict]:
        """Run one of the analytics queries in queries/ by file name, without .sql."""
        if name not in REPORTS:
            raise ValueError(f"unknown report {name!r}; choose from {sorted(REPORTS)}")
        return [dict(r) for r in self._db.execute(REPORTS[name])]
