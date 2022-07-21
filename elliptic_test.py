from x3dh.dh import X25519KeyPair
from x3dh.x25519 import scalar_mult, shared_secret

alice = X25519KeyPair()
bob = X25519KeyPair()
print(f"Shared: {shared_secret(alice.sk, bob.pk).hex()}")
print(f"Shared: {scalar_mult(alice.sk, bob.pk).hex()}")