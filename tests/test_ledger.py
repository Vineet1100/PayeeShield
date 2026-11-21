"""The SQLite ledger: analytics reports, parameterized queries and persistence."""

import os
import sqlite3
import stat
import time
from dataclasses import replace
from decimal import Decimal

import pytest

from bank.core import Bank, Transaction
from bank.ledger import Ledger


def tx(**changes) -> Transaction:
    approved = Transaction(
        at=time.time(),
        channel="online",
        card_ref="tok_test",
        merchant_id="coffee-shop",
        amount=Decimal("25.00"),
        approved=True,
        reason="approved by cardholder",
        security_block=False,
        hour=13,
    )
    return replace(approved, **changes)


def blocked(**changes) -> Transaction:
    return tx(approved=False, security_block=True, reason="incorrect CVV", **changes)


@pytest.fixture
def ledger():
    ledger = Ledger()
    ledger.add_transaction(tx(amount=Decimal("10.00")))
    ledger.add_transaction(tx(amount=Decimal("20.50"), hour=9))
    ledger.add_transaction(blocked())
    ledger.add_transaction(tx(channel="in_store", amount=Decimal("4.25")))
    ledger.add_transaction(blocked(channel="in_store"))
    return ledger


def test_approval_rate_by_channel(ledger):
    assert ledger.report("approval_rate_by_channel") == [
        {"channel": "in_store", "attempts": 2, "approved": 1, "approval_rate_pct": 50.0},
        {"channel": "online", "attempts": 3, "approved": 2, "approval_rate_pct": 66.7},
    ]


def test_blocked_by_reason(ledger):
    assert ledger.report("blocked_by_reason") == [
        {"reason": "incorrect CVV", "channel": "in_store", "attempts": 1},
        {"reason": "incorrect CVV", "channel": "online", "attempts": 1},
    ]


def test_hourly_volume_counts_only_approved_spending(ledger):
    assert ledger.report("hourly_volume") == [
        {"hour": 9, "attempts": 1, "approved": 1, "approved_volume": 20.5},
        {"hour": 13, "attempts": 4, "approved": 2, "approved_volume": 14.25},
    ]


def test_stats_are_exact_to_the_cent(ledger):
    assert ledger.stats() == {
        "attempts": 5,
        "approved": 3,
        "blocked": 2,
        "alerts": 0,
        "approved_volume": "34.75",
    }


def test_only_known_reports_can_run(ledger):
    with pytest.raises(ValueError, match="unknown report"):
        ledger.report("../bank/ledger")


def test_values_are_stored_as_data_not_sql():
    ledger = Ledger()
    hostile = "x'); DROP TABLE transactions; --"
    ledger.add_transaction(tx(merchant_id=hostile, reason=hostile))
    row = ledger._db.execute("SELECT merchant_id, reason FROM transactions").fetchone()
    assert tuple(row) == (hostile, hostile)


@pytest.mark.parametrize(
    "bad",
    [{"amount": Decimal("-5.00")}, {"channel": "atm"}, {"hour": 24}],
    ids=["amount", "channel", "hour"],
)
def test_schema_rejects_impossible_rows(bad):
    with pytest.raises(sqlite3.IntegrityError):
        Ledger().add_transaction(tx(**bad))


def test_ledger_file_is_private_and_survives_a_restart(settings):
    Bank(settings).ledger.add_transaction(tx())
    mode = stat.S_IMODE(os.stat(settings.ledger_path).st_mode)
    assert mode == 0o600
    assert Bank(settings).stats()["attempts"] == 1
