import hashlib
import x25519
from .kdf import KDF
from .utils import (
    x25519_clamp,
    x25519_keygen_private,
    x25519_keygen_public,
    x25519_shared_secret,
)

def x25519_dh_gen_shared_key(sk1: bytes, pk2: bytes) -> bytes:
    """ Returns KDF(`sk1` * `pk2`) where sk1 is your private key and pk2 is the other party's public key"""
    shared_secret = x25519_shared_secret(sk1, pk2)
    return KDF(shared_secret)


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
        return x25519_dh_gen_shared_key(self.__a, other_key)

    def save(self):
        return {
            "private": self.__a.hex(),
        }

    @classmethod
    def load(cls, data: dict):
        c = cls(private=bytes.fromhex(data["private"]))
        return c
