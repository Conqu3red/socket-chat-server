"""
Authenticated Encryption with Associated Data
CBC-HMAC algorithm paired with HMAC and SHA-256, and AES in CBC mode

ref: https://datatracker.ietf.org/doc/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05
"""

import hmac
import hashlib
import os
from typing import Optional
from Crypto.Cipher import AES

PADDING_TABLE = {
    120: b"\x01",
    112: b"\x02\x02",
    104: b"\x03\x03\x03",
    96:  b"\x04\x04\x04\x04",
    88:  b"\x05\x05\x05\x05\x05",
    80:  b"\x06\x06\x06\x06\x06\x06",
    72:  b"\x07\x07\x07\x07\x07\x07\x07",
    64:  b"\x08\x08\x08\x08\x08\x08\x08\x08",
    56:  b"\x09\x09\x09\x09\x09\x09\x09\x09\x09",
    48:  b"\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A",
    40:  b"\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B",
    32:  b"\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C",
    24:  b"\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D",
    16:  b"\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E",
    8:   b"\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F",
    0:   b"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10",
}

def pad_bytes(P: bytes) -> bytes:
    PS = PADDING_TABLE[(len(P) * 8) % 128]
    return P + PS

class AEAD:
    """ Class that implementes the AEAD using AES-CBC and HMAC-SHA """
    
    def __init__(self, ENC_KEY_LEN: int, MAC_KEY_LEN: int, T_LEN: int, sha_func):
        self.ENC_KEY_LEN = ENC_KEY_LEN
        self.MAC_KEY_LEN = MAC_KEY_LEN
        self.K_LEN = ENC_KEY_LEN + MAC_KEY_LEN
        self.T_LEN = T_LEN
        self.sha_func = sha_func

    def encrypt(self, K: bytes, P: bytes, A: bytes) -> bytes:
        """
        K : Secret Key
        P : Plaintext
        A : Associated Data

        Returns : Ciphertext
        """

        if len(K) != self.K_LEN:
            raise Exception("Key length is incorrect")

        MAC_KEY = K[:self.MAC_KEY_LEN]
        ENC_KEY = K[-self.ENC_KEY_LEN:]

        padded_P = pad_bytes(P)

        
        IV = os.urandom(16)
        cipher = AES.new(key=ENC_KEY, mode=AES.MODE_CBC, iv=IV)
        ciphertext = cipher.encrypt(padded_P)
        S = IV + ciphertext
        
        AL = len(A).to_bytes(64, "big") # network byte order
        hmac_obj = hmac.new(
            key = MAC_KEY,
            msg = A + S + AL,
            digestmod=self.sha_func
        )
        T = hmac_obj.digest()[:self.T_LEN]

        C = S + T
        return C


    def decrypt(self, K: bytes, A: bytes, C: bytes) -> Optional[bytes]:
        """
        K : Secret Key
        A : Associated Data
        C : Ciphertext

        Returns : Plaintext or `None` if decryption fails
        """

        if len(K) != self.K_LEN:
            raise Exception("Key length is incorrect")
        
        MAC_KEY = K[:self.MAC_KEY_LEN]
        ENC_KEY = K[-self.ENC_KEY_LEN:]

        S = C[:-self.T_LEN]
        IV = S[:16]
        ciphertext = S[16:]
        T = C[-self.T_LEN:] # T_LEN bytes from end of C
        
        AL = len(A).to_bytes(64, "big") # network byte order
        hmac_obj = hmac.new(
            key = MAC_KEY,
            msg = A + S + AL,
            digestmod=self.sha_func
        )
        expected_T = hmac_obj.digest()[:self.T_LEN]

        if expected_T != T:
            # Invalid A and C
            print("Invalid A and C")
            return None
        
        # A and C are considered valid
        cipher = AES.new(key=ENC_KEY, mode=AES.MODE_CBC, iv=IV)
        padded_P = cipher.decrypt(ciphertext)

        # remove padding
        padding_length = padded_P[-1]
        if 0x01 <= padding_length <= 0x10:
            # valid padding
            P = padded_P[:-padding_length]

            return P
        else:
            print(f"Invalid padding length {padding_length}")
            # padding was invalid, abort
            return None

AEAD_AES_128_CBC_HMAC_SHA_256 = AEAD(ENC_KEY_LEN=16, MAC_KEY_LEN=16, T_LEN=16, sha_func=hashlib.sha256)
AEAD_AES_192_CBC_HMAC_SHA_384 = AEAD(ENC_KEY_LEN=24, MAC_KEY_LEN=24, T_LEN=24, sha_func=hashlib.sha384)
AEAD_AES_256_CBC_HMAC_SHA_384 = AEAD(ENC_KEY_LEN=32, MAC_KEY_LEN=24, T_LEN=24, sha_func=hashlib.sha384)
AEAD_AES_256_CBC_HMAC_SHA_512 = AEAD(ENC_KEY_LEN=32, MAC_KEY_LEN=32, T_LEN=32, sha_func=hashlib.sha512)
