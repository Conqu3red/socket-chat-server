from x3dh.curve25519.curve25519 import scalar_mult
from x3dh.curve25519.x25519 import X25519, X25519KeyPair

alice = X25519KeyPair()
bob = X25519KeyPair()
print(f"Shared: {X25519(alice.sk, bob.pk).hex()}")
print(f"Shared: {scalar_mult(alice.sk, bob.pk).hex()}")