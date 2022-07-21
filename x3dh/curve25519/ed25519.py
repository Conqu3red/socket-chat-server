from typing import Tuple
from . import curve25519


def u_to_y(u: int) -> int:
    mod_inverse = lambda x: pow(x, curve25519.p - 2, curve25519.p)
    return (u - 1) * mod_inverse(u + 1)
    # mod_inverse replaces division


class TwistedEdwardsPoint:
    def __init__(self, y: int, s: int = 0):
        # self.x
        self.y = y
        self.s = s
        

def convert_mont(u: bytes) -> bytes:
    u_masked = curve25519.decodeUCoordinate(u, curve25519.bits)
    return TwistedEdwardsPoint(u_to_y(u_masked), 0)

BASE_POINT = convert_mont(curve25519.encodeLittleEndian(9, curve25519.bits))

def calculate_key_pair(k: bytes) -> Tuple[bytes, bytes]:
    """ Convert a Montgomery private key `k` to a twisted Edwards public key and private key (A, a) respectively"""

# TODO: finish impl
