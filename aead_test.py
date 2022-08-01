import os
from x3dh.aead import AEAD_AES_128_CBC_HMAC_SHA_256 as aead

key = os.urandom(32)
message = b"Hello!!"
associated_data = b"Associated"

enc = aead.encrypt(key, message, associated_data)
print(f"key: {enc.hex()}")
print(f"Decryption with correct AD: {aead.decrypt(key, associated_data, enc)}")
print(f"Decryption with wrong AD: {aead.decrypt(key, associated_data + b'abc', enc)}")