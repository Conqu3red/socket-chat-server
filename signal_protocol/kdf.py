import hashlib
import hmac
from math import ceil
from typing import Tuple

HASH_LEN = 32

# https://en.m.wikipedia.org/wiki/HKDF#Example:_Python_implementation
def hmac_sha256(key: bytes, data: bytes):
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf(length: int, ikm: bytes, salt: bytes = b"", info: bytes = b"") -> bytes:
    """ Key derivation function
    length : bytes to be returned
    ikm : initial key material
    salt : 
    info : 
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


def KDF_RK(rk: bytes, dh_out: bytes) -> Tuple[bytes, bytes]:
    """
    Returns a pair (32-byte root key, 32-byte chain key)
    as the output of applying a KDF keyed by a 32-byte root key rk
    to a Diffie-Hellman output dh_out.
    
    rk : root key
    dh_out : diffie hellman output
    """

    INFO_BYTES = b"TestApp_KDF_Chaining"

    r = hkdf(length=64, ikm=dh_out, salt=rk, info=INFO_BYTES)
    return (r[:32], r[32:])


def KDF_CK(ck: bytes) -> Tuple[bytes, bytes]:
    """
    Returns a pair (32-byte chain key, 32-byte message key) as
    the output of applying a KDF keyed by a 32-byte chain key ck to some constant.

    ck : chain key
    """

    new_ck = hmac_sha256(ck, b"\x01")
    new_mk = hmac_sha256(ck, b"\x02")

    return new_ck, new_mk
