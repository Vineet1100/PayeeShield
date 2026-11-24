"""Dynamic CVV codes: RFC 6238 time-based one-time passwords shortened to 3 digits.

pyotp 2.12 only allows codes of 6 to 10 digits. A TOTP code is the HMAC result taken
modulo 10**digits, so the last 3 digits of the 6-digit code are exactly the 3-digit
code: ``(n % 10**6) % 10**3 == n % 10**3``. The codes are the same as before, and this
works on every pyotp version.
"""

import datetime as dt

import pyotp

_FULL_DIGITS = 6


class DynamicCVV:
    """A TOTP generator that returns ``digits``-long codes (3 for a card's CVV)."""

    def __init__(self, secret: str, digits: int = 3, interval: int = 120):
        if not 1 <= digits <= _FULL_DIGITS:
            raise ValueError(f"digits must be between 1 and {_FULL_DIGITS}")
        self.digits = digits
        self._totp = pyotp.TOTP(secret, digits=_FULL_DIGITS, interval=interval)

    def at(self, for_time: float | dt.datetime) -> str:
        """The code for a moment in time (unix seconds or a datetime)."""
        return self._totp.at(for_time)[-self.digits :]

    def now(self) -> str:
        """The code shown on the card right now."""
        return self._totp.now()[-self.digits :]
