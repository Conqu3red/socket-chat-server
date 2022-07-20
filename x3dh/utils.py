import os
import x25519

def x25519_clamp(sk: bytes) -> bytes:
    """ Clamp a x25519 private key """
    return bytes(x25519.clamp(sk))

def x25519_keygen_private() -> bytes:
    """ Generate new private x25519 key """
    return x25519_clamp(os.urandom(32))

def x25519_keygen_public(sk: bytes) -> bytes:
    """ Generate public key from private key `sk` """
    return x25519.scalar_base_mult(sk)