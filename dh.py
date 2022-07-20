import os
import binascii
import hashlib
import x25519


def DH(sk1: bytes, pk2: bytes) -> bytes:
    return x25519.scalar_mult(sk1, pk2)


class DiffieHellman:
    """ Class to represent the Diffie-Hellman key exchange protocol using X25519 Elliptic Curve"""

    # Current minimum recommendation is 2048 bit.
    def __init__(self, private: str = None):
        if private is not None:
            self.__a = binascii.unhexlify(private)
        else:
            self.__a = os.urandom(32)

    def get_private_key(self) -> bytes:
        """ Return the private key (a) """
        return self.__a

    def get_private_key_hex(self) -> str:
        return binascii.hexlify(self.get_private_key()).decode("utf-8")

    def gen_public_key(self) -> bytes:
        """ Return aG mod p """
        return x25519.scalar_base_mult(self.__a)

    def gen_public_key_hex(self) -> str:
        return binascii.hexlify(self.gen_public_key()).decode("utf-8")

    def gen_shared_key(self, other_key: bytes) -> str:
        """ Return abG mod p """
        shared_key = DH(self.__a, other_key)
        print(shared_key)

        return hashlib.sha256(shared_key).hexdigest()

    def save(self):
        return {
            "private": binascii.hexlify(self.__a).decode("utf-8"),
        }

    @classmethod
    def load(cls, data: dict):
        c = cls(private=data["private"])
        return c
