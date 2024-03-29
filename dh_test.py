from x3dh.dh import X25519KeyPair, x25519_gen_shared_key

alice = X25519KeyPair()
bob = X25519KeyPair()

alice_shared = x25519_gen_shared_key(alice.sk, bob.pk)
bob_shared = x25519_gen_shared_key(bob.sk, alice.pk)

print(f"Alice shared key: {alice_shared.hex()}")
print(f"Bob shared key: {bob_shared.hex()}")
print(f"Equal? {alice_shared == bob_shared}")