from x3dh.dh import DiffieHellman

alice = DiffieHellman()
bob = DiffieHellman()

alice_shared = alice.gen_shared_key(bob.gen_public_key())
bob_shared = bob.gen_shared_key(alice.gen_public_key())

print(f"Alice shared key: {alice_shared.hex()}")
print(f"Bob shared key: {bob_shared.hex()}")
print(f"Equal? {alice_shared == bob_shared}")