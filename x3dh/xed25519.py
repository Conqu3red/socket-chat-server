"""
Implemetation of the XEdDSA signature scheme using Curve25519 elliptic curve.

This module allow you to create and verify EdDSA-compatible signatures
using public key and private key formats initially defined for the X25519
elliptic curve Diffie-Hellman functions.
"""

import os
from .curve25519 import ed25519
import hashlib
from typing import Optional


def hash_and_decode_int(X: bytes) -> int:
    return int.from_bytes(hashlib.sha512(X).digest(), "little")


def hash_i(i: int, X: bytes) -> int:
    n: int = (2 ** ed25519.rounded_bits) - 1 - i
    prefix = n.to_bytes(ed25519.rounded_bits // 8, "little")
    return hash_and_decode_int(prefix + X)


def sign(k: bytes, M: bytes, Z: Optional[bytes] = None) -> bytes:
    """
    k : Montgomery private key (integer mod q)
    M : Message to sign (byte sequence)
    Z : 64 bytes secure random data (byte sequence)
    """
    
    if Z is not None:
        assert len(Z) == 64
    else:
        Z = os.urandom(64)

    A, a = ed25519.calculate_key_pair(k)
    r = hash_i(1, a + M + Z) % ed25519.q
    R = ed25519.TwistedEdwardsPoint.BASE_POINT.to_homogeneous().scalar_multiply(r).to_actual().compress()
    h = hash_and_decode_int(R + A + M) % ed25519.q
    s = (r + h * int.from_bytes(a, "little")) % ed25519.q
    return R + s.to_bytes(32, "little")


def verify(u: bytes, M: bytes, R_s: bytes) -> bool:
    """
    u : Montgomery public key (byte sequence of b bits)
    M : Message to verify (byte sequence)
    R_s : Signature to verify (byte sequence of 2b bits)
    """
    assert len(R_s) == 64 # bytes
    _u = int.from_bytes(u, "little")
    R = ed25519.TwistedEdwardsPoint.decompress(R_s[:32])
    if R is None:
        return False
    s = int.from_bytes(R_s[32:], "little")
    
    if _u >= ed25519.p or R.y >= 1 << ed25519.p_bits or s >= 1 << ed25519.q_bits:
        return False
    A = ed25519.convert_mont(u)
    
    if not A.on_curve():
        return False
    
    h = hash_and_decode_int(R.compress() + A.compress() + M) % ed25519.q
    sB = ed25519.TwistedEdwardsPoint.BASE_POINT.to_homogeneous().scalar_multiply(s)
    hA = A.to_homogeneous().scalar_multiply(h)
    Rcheck = sB.subtract(hA).to_actual()
    
    if R.compress() == Rcheck.compress():
        return True
    return False