import os
from typing import Optional
from . import curve25519

# https://www.ietf.org/rfc/rfc7748.txt (page 8-9)


def clamp(sk: bytes) -> bytes:
    """ Clamp a x25519 private key """
    mut = bytearray(sk)
    mut[0] &= 248 # unset the 3 least significant bits
    mut[31] &= 127 # unset the most significant bit
    mut[31] |= 64 # set the second most significant bit
    return bytes(mut)


def keygen_private() -> bytes:
    """ Generate new x25519 private key """
    return clamp(os.urandom(32))


def keygen_public(sk: bytes) -> bytes:
    """ Generate a x25519 public key from private key `sk` """
    return curve25519.scalar_base_mult(sk)


def X25519(sk1: bytes, pk2: bytes) -> bytes: # TODO? better name??
    """ `sk1` * `pk2` where `sk1` is a private key and `pk2` is a public key  """
    return curve25519.scalar_mult(sk1, pk2)


class X25519KeyPair:
    """ Class for a key pair on the X25519 Elliptic Curve """
    
    def __init__(self, sk: Optional[bytes] = None):
        if sk is not None:
            self.sk = clamp(sk)
        else:
            self.sk = keygen_private()
        
        self.pk = keygen_public(self.sk)
