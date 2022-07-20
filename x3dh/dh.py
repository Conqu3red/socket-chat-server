from typing import Optional
from .kdf import KDF
from .utils import (
    x25519_clamp,
    x25519_keygen_private,
    x25519_keygen_public,
    x25519_shared_secret,
)


def x25519_gen_shared_key(sk1: bytes, pk2: bytes) -> bytes:
    """
    Generates a shared secret and passes it through the key derivation function.
    
    Shared secret is computed from your private key `sk1` and the other party's public key `pk2`
    """
    shared_secret = x25519_shared_secret(sk1, pk2)
    return KDF(shared_secret)


class X25519KeyPair:
    """ Class for a key pair on the X25519 Elliptic Curve """
    
    def __init__(self, sk: Optional[bytes] = None):
        if sk is not None:
            self.sk = x25519_clamp(sk)
        else:
            self.sk = x25519_keygen_private()
        
        self.pk = x25519_keygen_public(self.sk)
