import os
import x25519

# https://www.ietf.org/rfc/rfc7748.txt (page 7)
def x25519_clamp(sk: bytes) -> bytes:
    """ Clamp a x25519 private key """
    mut = bytearray(sk)
    mut[0] &= 248 # unset the 3 least significant bits
    mut[31] &= 127 # unset the most significant bit
    mut[31] |= 64 # set the second most significant bit
    return bytes(mut)


def x25519_keygen_private() -> bytes:
    """ Generate new private x25519 key """
    return x25519_clamp(os.urandom(32))


def x25519_keygen_public(sk: bytes) -> bytes:
    """ Generate public key from private key `sk` """
    return x25519.scalar_base_mult(sk)


def x25519_shared_secret(sk1: bytes, pk2: bytes) -> bytes:
    """ `sk1` * `pk2` where `sk1` is a private key and `pk2` is a public key  """
    return x25519.scalar_mult(sk1, pk2)
