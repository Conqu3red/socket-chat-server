import os
from typing import Tuple

# https://www.ietf.org/rfc/rfc7748.txt (page 8-9)
p = (2 ** 255) - 19
bits = 256 # curve 25519
a24 = (486662 - 2) // 4 # 121665


def decodeLittleEndian(b: int, bits: int) -> bytes:
    return sum([b[i] << 8 * i for i in range((bits + 7) // 8)])


def encodeLittleEndian(n: int, bits: int):
    return bytes([(n >> 8 * i) & 0xff for i in range((bits + 7) // 8)])


def decodeUCoordinate(u: bytes, bits: int) -> int:
    u_list = [b for b in u]
    # Ignore any unused bits.
    if bits % 8:
        u_list[-1] &= (1 << (bits % 8)) - 1
    return decodeLittleEndian(u_list, bits)


def encodeUCoordinate(u: int, bits: int) -> bytes:
    u = u % p
    return encodeLittleEndian(u, bits)


BASE_POINT = encodeUCoordinate(9, bits)


def cswap(swap: int, x_2: int, x_3: int) -> Tuple[int, int]:
    # TODO: constant time version (this isn't secure and is prone to side-channel/timing attacks etc)
    return (x_3, x_2) if swap else (x_2, x_3)


def scalar_mult(k: bytes, u: bytes) -> bytes:
    """
    Multiply the point u on the x25519 elliptic curve by the scalar k
    Args:
        k : scalar value
        u : coordinate
    """
    _k = decodeLittleEndian(k, bits)
    _u = decodeUCoordinate(u, bits)
    
    x_1 = _u
    x_2 = 1
    z_2 = 0
    x_3 = _u
    z_3 = 1
    swap = 0

    for t in range(bits - 1, -1, -1):
        #print(t)
        k_t = (_k >> t) & 1
        swap ^= k_t
        # Conditional swap; see text below.
        (x_2, x_3) = cswap(swap, x_2, x_3)
        (z_2, z_3) = cswap(swap, z_2, z_3)
        swap = k_t

        A = (x_2 + z_2) % p
        AA = pow(A, 2, p)
        B = (x_2 - z_2) % p
        BB = pow(B, 2, p)
        E = (AA - BB) % p
        C = (x_3 + z_3) % p
        D = (x_3 - z_3) % p
        DA = (D * A) % p
        CB = (C * B) % p
        x_3 = pow((DA + CB), 2, p)
        z_3 = x_1 * pow((DA - CB), 2, p)
        x_2 = (AA * BB) % p
        z_2 = (E * (AA + a24 * E)) % p

    # Conditional swap; see text below.
    (x_2, x_3) = cswap(swap, x_2, x_3)
    (z_2, z_3) = cswap(swap, z_2, z_3)
    return encodeUCoordinate(x_2 * pow(z_2, (p - 2), p), bits)


def scalar_base_mult(k: bytes) -> bytes:
    """ multiply the base point (u=9) by the constant k """
    return scalar_mult(k, BASE_POINT)


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
    """ Generate public key from private key `sk` """
    return scalar_base_mult(sk)


def shared_secret(sk1: bytes, pk2: bytes) -> bytes:
    """ `sk1` * `pk2` where `sk1` is a private key and `pk2` is a public key  """
    return scalar_mult(sk1, pk2)