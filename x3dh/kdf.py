import hashlib
import hmac
from math import ceil

HASH_LEN = 32

# https://en.m.wikipedia.org/wiki/HKDF#Example:_Python_implementation
def hmac_sha256(key: bytes, data: bytes):
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf(length: int, ikm: bytes, salt: bytes = b"", info: bytes = b"") -> bytes:
    """ Key derivation function
    """
    if len(salt) == 0:
        salt = bytes([0] * HASH_LEN)
    prk = hmac_sha256(salt, ikm)
    t = b""
    okm = b""
    
    for i in range(ceil(length / HASH_LEN)):
        t = hmac_sha256(prk, t + info + bytes([i + 1]))
        okm += t
    
    return okm[:length]


def KDF(KM: bytes, info: bytes = b"") -> bytes:
    """run HKDF algorithm in `KM` (Key Material) with `info`"""
    # this code assumes the x25519 curve
    F = bytes([0xFF] * 32)
    return hkdf(32, ikm = F + KM, salt = bytes([0] * 32), info = info)
