from .kdf import KDF
from .curve25519 import x25519


def x25519_gen_shared_key(sk1: bytes, pk2: bytes) -> bytes:
    """
    Generates a shared secret and passes it through the key derivation function.
    
    Shared secret is computed from your private key `sk1` and the other party's public key `pk2`
    """
    shared_secret = x25519.X25519(sk1, pk2)
    return KDF(shared_secret)
