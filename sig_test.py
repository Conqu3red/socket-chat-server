from x3dh.utils import x25519_keygen_private, x25519_keygen_public
from x3dh.sig import Sign, Verify

sk = x25519_keygen_private()
pk = x25519_keygen_public(sk)

message = "hello!"
signature = Sign(sk, message.encode("utf-8"))
print(f"Signature: {signature}")

verified = Verify(pk, message.encode("utf-8"), signature)
print(f"Verified: {verified}")

