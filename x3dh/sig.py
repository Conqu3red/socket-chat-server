from xeddsa.implementations.xeddsa25519 import XEdDSA25519
from typing import *

def Sign(k: bytes, M: bytes, Z: Optional[bytes] = None) -> bytes:
    """
    k : Montgomery private key (integer mod q)
    M : Message to sign (byte sequence)
    Z: 64 bytes secure random data (byte sequence)
    """
    if Z is not None:
        assert len(Z) == 64
    
    curve = XEdDSA25519(mont_priv=k)
    return curve.sign(data=M, nonce=Z)


def Verify(u: bytes, M: bytes, R_s: bytes) -> bool:
    """
    u : Montgomery public key (byte sequence of b bits)
    
    M : Message to verify (byte sequence)
    
    R_s : Signature to verify (byte sequence of 2b bits)
    """
    curve = XEdDSA25519(mont_pub=u)
    return curve.verify(data=M, signature=R_s)
