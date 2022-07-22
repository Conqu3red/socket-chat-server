from x3dh.curve25519.ed25519 import TwistedEdwardsPoint

""" sk = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
test_pk = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
pk = ed25519.scalar_mult(sk, ed25519.BASE_POINT)

print(test_pk.hex())
print(pk.hex())

assert test_pk == pk """
""" _y = 46316835694926478169428394003475163141307993866256225615783033603165251855960
y = _y.to_bytes(32, "little")
c = ed25519.TwistedEdwardsPoint.decompress(y)
print(c)
print(c.x)
print(c.y) """

sk = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
test_pk = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")

_sk = int.from_bytes(sk, "little")

h_r = TwistedEdwardsPoint.BASE_POINT.to_homogeneous().scalar_multiply(_sk)
r = h_r.to_affine()

print("result:")
print(r.y.to_bytes(32, "little").hex())

print("t:")
print(TwistedEdwardsPoint.BASE_POINT)
print(TwistedEdwardsPoint.BASE_POINT.to_homogeneous().to_affine())
