from typing import Optional, Tuple
from .utils import decodeLittleEndian, encodeLittleEndian
from . import curve25519
from .curve25519 import p
from math import log2, ceil


def inv_modp(n: int) -> int:
    return pow(n, p - 2, p)


d = -121665 * inv_modp(121666) % p
q: int = 2 ** 252 + 27742317777372353535851937790883648493
q_bits = ceil(log2(q))


def u_to_y(u: int) -> int:
    return ((u - 1) * inv_modp(u + 1)) % p
    # mod_inverse replaces division


class TwistedEdwardsPoint:
    BASE_POINT: 'TwistedEdwardsPoint'

    def __init__(self, x: int, y: int):
        self.x = x
        self.y = y
    
    def set_sign(self, sign: int):
        self.x ^= (sign & 1) ^ (self.x & 1)
    
    @property
    def s(self) -> int:
        return (self.x & 1)
    
    @s.setter
    def s(self, value: int):
        self.set_sign(value)
    
    def on_curve(self) -> bool:
        xx = (self.x * self.x) % p
        yy = (self.y * self.y) % p
        lhs = (-xx + yy) % p
        rhs = (1 + d * xx * yy) % p
        return lhs == rhs
    
    @classmethod
    def decompress(cls, data: bytes) -> Optional['TwistedEdwardsPoint']:
        """ implements decompression defined in rfc8032 section 5.1.3 given the raw bytes """
        y = int.from_bytes(data, "little")
        return cls.decode(y)
    
    @classmethod
    def decode(cls, y: int) -> Optional['TwistedEdwardsPoint']:
        """ implements decompression defined in rfc8032 section 5.1.3 given an int `y` """
        sign = (y >> 255) & 1 # read sign bit
        #print(f"sign: {sign}")
        y ^= y & (1 << 255) # clear sign bit
        if y >= p:
            return None # y is larger than p
        
        yy = y * y
        xx = (yy - 1) * inv_modp(d * yy + 1)
        if xx == 0:
            return None if sign else cls(0, y)
        
        x = pow(xx, (p + 3) // 8, p) # square root candidate


        if (x * x - xx) % p != 0:
            x = (x * pow(2, (p - 1) // 4, p)) % p
        
        if (x * x - xx) % p != 0:
            return None # no square roots
        
        if sign != x & 1:
            x = p - x

        return cls(x, y)
    
    def compress(self) -> bytes:
        return self.encode().to_bytes(32, "little")

    def encode(self) -> int:
        return self.y ^ ((self.y >> 255 & 1) ^ (self.x & 1)) << 255 # clear MSB if required
    
    def to_homogeneous(self) -> 'HomogeneousPoint':
        return HomogeneousPoint(self.x, self.y, 1, (self.x * self.y) % p)
    
    def __repr__(self):
        return f"{self.__class__.__name__}(x={self.x}, y={self.y})"
    
    def __eq__(self, other: 'TwistedEdwardsPoint') -> bool:
        return self.x == other.x and self.y == other.y


class HomogeneousPoint:
    def __init__(self, X: int, Y: int, Z: int, T: int) -> None:
        self.X = X
        self.Y = Y
        self.Z = Z
        self.T = T
    
    def negate(self) -> 'HomogeneousPoint':
        return HomogeneousPoint(-self.X % p, self.Y, self.Z, -self.T % p)
    
    def add(self, other: 'HomogeneousPoint') -> 'HomogeneousPoint':
        """ returns a new point that is the "addition" of `self` and `other` """
        # all operations are done GF(p) - mod p
        X1, Y1, Z1, T1 = self.X, self.Y, self.Z, self.T
        X2, Y2, Z2, T2 = other.X, other.Y, other.Z, other.T

        A = ((Y1-X1) * (Y2-X2)) % p
        B = ((Y1+X1) * (Y2+X2)) % p
        C = (T1 * 2 * d * T2) % p
        D = (Z1 * 2 * Z2) % p
        E = (B - A) % p
        F = (D - C) % p
        G = (D + C) % p
        H = (B + A) % p
        
        X3 = (E * F) % p
        Y3 = (G * H) % p
        T3 = (E * H) % p
        Z3 = (F * G) % p

        # TODO, should this be written as self.__class__?
        return HomogeneousPoint(X3, Y3, Z3, T3)
    
    def subtract(self, other: 'HomogeneousPoint') -> 'HomogeneousPoint':
        return self.add(other.negate())


    def double(self) -> 'HomogeneousPoint':
        X1, Y1, Z1, T1 = self.X, self.Y, self.Z, self.T
        A = (X1 * X1) % p
        B = (Y1 * Y1) % p
        C = (2 * Z1 * Z1) % p
        H = (A + B) % p
        E = (H - (X1 + Y1) * (X1 + Y1)) % p
        G = (A - B) % p
        F = (C + G) % p
        X3 = (E * F) % p
        Y3 = (G * H) % p
        T3 = (E * H) % p
        Z3 = (F * G) % p

        return HomogeneousPoint(X3, Y3, Z3, T3)
    
    def scalar_multiply(self, k: int) -> 'HomogeneousPoint':
        """ Scalar multiplication using something similar to the montgomery ladder I think """
        R0 = HomogeneousPoint(0, 1, 1, 0)
        R1 = self
        for i in range(curve25519.bits, -1, -1):
            bit = (k >> i) & 1
            if bit == 0:
                R1 = R0.add(R1)
                R0 = R0.double()
            else:
                R0 = R0.add(R1)
                R1 = R1.double()
        
        return R0

    def to_actual(self) -> TwistedEdwardsPoint:
        inv_z = inv_modp(self.Z)
        return TwistedEdwardsPoint((self.X * inv_z) % p, (self.Y * inv_z) % p)
    
    def __repr__(self):
        return f"{self.__class__.__name__}(X={self.X}, Y={self.Y}, Z={self.Z}, T={self.T})"


def set_sign_bit(y: int, s: int) -> int:
    # sign bit is MSB of MSB octet (byte)
    y ^= (-s ^ y) & 1 << (curve25519.bits - 1)
    return y


p_bits = ceil(log2(p))
rounded_bits = 8 * ceil((p_bits + 1) / 8)

# TODO: wrapper types on points that have util functions on etc
def convert_mont(u: bytes) -> TwistedEdwardsPoint:
    """ Convert from a Montgomery u-coordinate to a twisted Edwards point """
    u_masked = decodeLittleEndian(u, curve25519.bits) % (1 << p_bits)
    y = u_to_y(u_masked)
    y ^= (y >> 255 & 1) << 255
    return TwistedEdwardsPoint.decode(y)

TwistedEdwardsPoint.BASE_POINT = TwistedEdwardsPoint.decode(
    u_to_y(9) # u = 9 (montgomery curve base u)
)


#BASE_POINT = convert_mont(curve25519.encodeLittleEndian(9, curve25519.bits))

# The following functions assume Z_1 = 1


def calculate_key_pair(k: bytes) -> Tuple[bytes, bytes]:
    """ Convert a Montgomery private key `k` to a twisted Edwards public key and private key (A, a) respectively"""
    _k = int.from_bytes(k, "little")
    E = TwistedEdwardsPoint.BASE_POINT.to_homogeneous().scalar_multiply(_k).to_actual()
    A = TwistedEdwardsPoint(E.x, E.y)
    A.s = 0
    if E.s == 1:
        a = -_k % q
    else:
        a = _k % q
    
    return A.compress(), a.to_bytes(32, "little")

# TODO: finish impl
