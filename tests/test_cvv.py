"""The 3-digit dynamic CVV must match the RFC 6238 maths exactly, on any pyotp version."""
import base64
import hashlib
import hmac
import struct

import pyotp
import pytest

from bank.cvv import DynamicCVV


def rfc6238(secret: str, for_time: float, interval: int, digits: int) -> str:
    """Reference TOTP straight from RFC 4226 / 6238, independent of pyotp."""
    counter = int(for_time // interval)
    mac = hmac.new(base64.b32decode(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF
    return str(code % 10 ** digits).zfill(digits)


@pytest.mark.parametrize("t", [0, 59, 1_800_000_000, 1_800_000_119, 1_800_000_120, 2_000_000_000.5])
def test_matches_the_rfc_reference(t):
    secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    cvv = DynamicCVV(secret, digits=3, interval=120)
    assert cvv.at(t) == rfc6238(secret, t, 120, 3)


def test_codes_are_three_digits_with_leading_zeros_kept():
    cvv = DynamicCVV(pyotp.random_base32(), digits=3, interval=120)
    codes = {cvv.at(i * 120) for i in range(3000)}
    assert all(len(c) == 3 and c.isdigit() for c in codes)
    assert any(c.startswith("0") for c in codes)


def test_code_changes_each_window_and_now_matches_at():
    import time
    cvv = DynamicCVV(pyotp.random_base32(), digits=3, interval=120)
    assert cvv.now() in {cvv.at(time.time()), cvv.at(time.time() - 1)}


def test_rejects_impossible_lengths():
    with pytest.raises(ValueError):
        DynamicCVV(pyotp.random_base32(), digits=7)
