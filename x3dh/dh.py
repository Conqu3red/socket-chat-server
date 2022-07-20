import hashlib
import x25519
from .kdf import KDF
from .utils import x25519_clamp, x25519_keygen_private, x25519_keygen_public

def DH(sk1: bytes, pk2: bytes) -> bytes:
    return x25519.scalar_mult(sk1, pk2)


class DiffieHellman:
    """ Class to represent the Diffie-Hellman key exchange protocol using X25519 Elliptic Curve """

    # Current minimum recommendation is 2048 bit.
    def __init__(self, private: bytes = None):
        if private is not None:
            self.__a = x25519_clamp(private)
        else:
            self.__a = x25519_keygen_private()

    def get_private_key(self) -> bytes:
        """ Return the private key (a) """
        return self.__a

    def gen_public_key(self) -> bytes:
        """ Return aG mod p """
        return x25519_keygen_public(self.__a)

    def gen_shared_key(self, other_key: bytes) -> bytes:
        """ Return abG mod p """
        shared_key = DH(self.__a, other_key)
        #print("Generated shared key:", shared_key)

        return KDF(shared_key)

    def save(self):
        return {
            "private": self.__a.hex(),
        }

    @classmethod
    def load(cls, data: dict):
        c = cls(private=bytes.fromhex(data["private"]))
        return c
