from x3dh.curve25519 import x25519
from x3dh.sig import Sign, Verify

sk = x25519.keygen_private()
pk = x25519.keygen_public(sk)

message = "hello!"
signature = Sign(sk, message.encode("utf-8"))
print(f"Signature: {signature}")

verified = Verify(pk, message.encode("utf-8"), signature)
print(f"Verified: {verified}")

