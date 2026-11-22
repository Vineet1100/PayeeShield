"""Authorization decisions and the fraud monitor.

Merchants only ever get a generic response code. The detailed reason goes to the
audit log and the alerts, which only bank-side clients can read.
"""

import hmac
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from decimal import Decimal

from . import fraud
from .config import Settings
from .cvv import DynamicCVV
from .ledger import Ledger
from .security import approval_signature, card_cryptogram, tokenize

APPROVED = "00"  # ISO 8583 style response codes
DECLINED = "05"  # "do not honour" - deliberately vague
PENDING = "P1"  # waiting for the cardholder to approve

MAX_CVV_FAILURES = 3
CVV_LOCKOUT_SECONDS = 60
APPROVAL_TTL_SECONDS = 60
BURST_WINDOW_SECONDS = 300
BURST_THRESHOLD = 3


@dataclass
class Transaction:
    at: float
    channel: str
    card_ref: str
    merchant_id: str
    amount: Decimal
    approved: bool
    reason: str
    security_block: bool
    hour: int


@dataclass
class Approval:
    id: str
    amount: Decimal
    merchant_id: str
    card_ref: str
    expires_at: float


@dataclass
class Bank:
    settings: Settings
    # local hour, a fraud-model feature
    hour_now: Callable[[], int] = lambda: time.localtime().tm_hour
    ledger: Ledger = field(init=False)
    _approvals: dict[str, Approval] = field(default_factory=dict)
    _used_cvv_steps: set[int] = field(default_factory=set)
    _cvv_failures: int = 0
    _online_blocked_until: float = 0.0
    _last_atc: int = -1
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self):
        self.ledger = Ledger(self.settings.ledger_path)

    # --- helpers

    def card_ref(self, pan: str) -> str:
        return tokenize(self.settings.token_key, pan)

    def _record(self, channel, pan, merchant_id, amount, approved, reason, block=False):
        tx = Transaction(
            at=time.time(),
            channel=channel,
            card_ref=self.card_ref(pan),
            merchant_id=merchant_id,
            amount=amount,
            approved=approved,
            reason=reason,
            security_block=block,
            hour=self.hour_now(),
        )
        self._monitor(self.ledger.add_transaction(tx), tx)
        return tx

    def _totp(self) -> DynamicCVV:
        return DynamicCVV(
            self.settings.card_otp_secret, digits=3, interval=self.settings.cvv_step_seconds
        )

    # --- in store

    def authorize_in_store(self, pan, amount: Decimal, merchant_id, atc: int, cryptogram: str):
        with self._lock:
            if pan != self.settings.card_pan:
                return DECLINED, self._record(
                    "in_store", pan, merchant_id, amount, False, "unknown card"
                )
            expected = card_cryptogram(
                self.settings.card_key, pan, int(amount * 100), merchant_id, atc
            )
            if not hmac.compare_digest(expected, cryptogram):
                return DECLINED, self._record(
                    "in_store",
                    pan,
                    merchant_id,
                    amount,
                    False,
                    "invalid cryptogram (chip locked or forged)",
                    block=True,
                )
            if atc <= self._last_atc:
                return DECLINED, self._record(
                    "in_store",
                    pan,
                    merchant_id,
                    amount,
                    False,
                    "replayed cryptogram (counter did not increase)",
                    block=True,
                )
            self._last_atc = atc
            return APPROVED, self._record(
                "in_store", pan, merchant_id, amount, True, "chip cryptogram valid"
            )

    # --- online

    def authorize_online(self, pan, cvv, amount: Decimal, merchant_id):
        with self._lock:
            now = time.monotonic()
            if pan != self.settings.card_pan:
                return (
                    DECLINED,
                    None,
                    self._record("online", pan, merchant_id, amount, False, "unknown card"),
                )
            if now < self._online_blocked_until:
                return (
                    DECLINED,
                    None,
                    self._record(
                        "online",
                        pan,
                        merchant_id,
                        amount,
                        False,
                        "online payments paused after repeated wrong CVVs",
                        block=True,
                    ),
                )

            totp = self._totp()
            step = int(time.time() // self.settings.cvv_step_seconds)
            if not hmac.compare_digest(cvv, totp.at(step * self.settings.cvv_step_seconds)):
                self._cvv_failures += 1
                stale = any(
                    hmac.compare_digest(cvv, totp.at((step - k) * self.settings.cvv_step_seconds))
                    for k in range(1, 5)
                )
                reason = "expired CVV (likely leaked card data)" if stale else "incorrect CVV"
                if self._cvv_failures >= MAX_CVV_FAILURES:
                    self._online_blocked_until = now + CVV_LOCKOUT_SECONDS
                    self._cvv_failures = 0
                    reason += "; online payments paused"
                return (
                    DECLINED,
                    None,
                    self._record("online", pan, merchant_id, amount, False, reason, block=True),
                )

            if step in self._used_cvv_steps:
                return (
                    DECLINED,
                    None,
                    self._record(
                        "online",
                        pan,
                        merchant_id,
                        amount,
                        False,
                        "CVV already used (replay)",
                        block=True,
                    ),
                )
            self._used_cvv_steps = {s for s in self._used_cvv_steps if s >= step - 2} | {step}
            self._cvv_failures = 0

            approval = Approval(
                id=secrets.token_urlsafe(16),
                amount=amount,
                merchant_id=merchant_id,
                card_ref=self.card_ref(pan),
                expires_at=now + APPROVAL_TTL_SECONDS,
            )
            self._approvals[approval.id] = approval
            return PENDING, approval, None

    def decide(self, approval_id: str, decision: str, signature: str):
        """The cardholder's device answers the push. Returns None for an unknown id."""
        with self._lock:
            approval = self._approvals.pop(approval_id, None)
            if approval is None:
                return None
            pan = self.settings.card_pan
            if time.monotonic() > approval.expires_at:
                return DECLINED, self._record(
                    "online", pan, approval.merchant_id, approval.amount, False, "approval expired"
                )
            expected = approval_signature(self.settings.device_key, approval_id, decision)
            if not hmac.compare_digest(expected, signature):
                return DECLINED, self._record(
                    "online",
                    pan,
                    approval.merchant_id,
                    approval.amount,
                    False,
                    "approval not signed by the cardholder's device",
                    block=True,
                )
            if decision == "deny":
                return DECLINED, self._record(
                    "online",
                    pan,
                    approval.merchant_id,
                    approval.amount,
                    False,
                    "cardholder denied the purchase",
                    block=True,
                )
            return APPROVED, self._record(
                "online", pan, approval.merchant_id, approval.amount, True, "approved by cardholder"
            )

    # --- fraud monitor

    def _monitor(self, tx_id: int, tx: Transaction) -> None:
        if tx.security_block:
            recent = self.ledger.blocked_since(tx.channel, tx.at - BURST_WINDOW_SECONDS)
            if recent == BURST_THRESHOLD:
                title = f"{BURST_THRESHOLD} blocked {tx.channel} attempts in 5 minutes"
                self.ledger.add_alert(tx_id, "high", title)
        if "expired CVV" in tx.reason:
            self.ledger.add_alert(tx_id, "high", "stolen card data used online")
        if "denied" in tx.reason:
            self.ledger.add_alert(tx_id, "high", "purchase denied by cardholder")
        if tx.approved:
            result = fraud.score(float(tx.amount), tx.hour, tx.channel == "online")
            if result.flagged:
                self.ledger.add_alert(tx_id, "medium", f"unusual purchase: {result.reason}")

    def pending(self) -> list[Approval]:
        with self._lock:
            now = time.monotonic()
            return [a for a in self._approvals.values() if a.expires_at > now]

    def alerts(self, limit: int) -> list[dict]:
        with self._lock:
            return self.ledger.alerts(limit)

    def stats(self) -> dict:
        with self._lock:
            return self.ledger.stats()

    def report(self, name: str) -> list[dict]:
        with self._lock:
            return self.ledger.report(name)
