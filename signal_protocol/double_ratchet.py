from dataclasses import dataclass
from typing import Dict, Tuple, Optional
from .curve25519 import x25519
from . import kdf
from .aead import AEAD_AES_128_CBC_HMAC_SHA_256 as aead

MAX_SKIP = 100

@dataclass
class Header:
    dh: bytes # dh public key
    pn: int # previous chain length
    n: int # message number

    def encode(self) -> bytes:
        return self.dh + self.pn.to_bytes(8, "little") + self.n.to_bytes(8, "little")
    
    @classmethod
    def decode(cls, data: bytes):
        return cls(
            dh=data[:32],
            pn=int.from_bytes(data[32:40], "little"),
            n=int.from_bytes(data[40:48], "little")
        )


def create_header(dh_pair: x25519.X25519KeyPair, pn: int, n: int) -> Header:
    return Header(dh_pair.pk, pn, n)


def encode_maybe_bytes(data: Optional[bytes]):
    if data is not None:
        return data.hex()


def decode_maybe_bytes(data: Optional[str]):
    if data is not None:
        return bytes.fromhex(data)


def parse_mkskipped_index(index: str) -> Tuple[bytes, int]:
    parts = index.split("-")
    ratchet_key = bytes.fromhex(parts[0])
    n = int(parts[1])
    return ratchet_key, n


@dataclass
class State:
    """
    DHs: DH Ratchet key pair (the "sending" or "self" ratchet key)

    DHr: DH Ratchet public key (the "received" or "remote" key)

    RK: 32-byte Root Key

    CKs, CKr: 32-byte Chain Keys for sending and receiving

    Ns, Nr: Message numbers for sending and receiving

    PN: Number of messages in previous sending chain

    MKSKIPPED: Dictionary of skipped-over message keys,
    indexed by ratchet public key and message number.
    Raises an exception if too many elements are stored.
    """

    DHs: x25519.X25519KeyPair
    DHr: Optional[bytes]
    RK: bytes
    CKs: Optional[bytes]
    CKr: Optional[bytes]
    Ns: int
    Nr: int
    PN: int
    MKSKIPPED: Dict[Tuple[bytes, int], bytes]

    def to_json(self):
        return {
            "DHs": self.DHs.to_json(),
            "DHr": encode_maybe_bytes(self.DHr),
            "RK": self.RK.hex(),
            "CKs": encode_maybe_bytes(self.CKs),
            "CKr": encode_maybe_bytes(self.CKr),
            "Ns": self.Ns,
            "Nr": self.Nr,
            "PN": self.PN,
            "MKSKIPPED": {
                f"{ratchet_public_key.hex()}-{n}": key.hex()
                for (ratchet_public_key, n), key in self.MKSKIPPED.items()
            }
        }
    
    @classmethod
    def from_json(cls, data):
        return cls(
            DHs = x25519.X25519KeyPair.from_json(data["DHs"]),
            DHr = decode_maybe_bytes(data["DHr"]),
            RK = bytes.fromhex(data["RK"]),
            CKs = decode_maybe_bytes(data["CKs"]),
            CKr = decode_maybe_bytes(data["CKr"]),
            Ns = data["Ns"],
            Nr = data["Nr"],
            PN = data["PN"],
            MKSKIPPED = {
                parse_mkskipped_index(index): bytes.fromhex(key)
                for index, key in data["MKSKIPPED"].items()
            }
        )


def ratchetInitAsFirstSender(SK: bytes, other_dh_public_key: bytes):
    """ Initialises ratchet for user who initiated the conversation """
    state = State(
        DHs = x25519.X25519KeyPair(),
        DHr = other_dh_public_key,
        RK = b"",
        CKs = b"",
        CKr = None,
        Ns = 0,
        Nr = 0,
        PN = 0,
        MKSKIPPED = {},
    )

    state.RK, state.CKs = kdf.KDF_RK(SK, x25519.X25519(state.DHs.sk, state.DHr))
    return state


def ratchetInitAsFirstReciever(SK: bytes, dh_key_pair: x25519.X25519KeyPair):
    """ Initialises ratchet for user who recieved the conversation """
    state = State(
        DHs = dh_key_pair,
        DHr = None,
        RK = SK,
        CKs = None,
        CKr = None,
        Ns = 0,
        Nr = 0,
        PN = 0,
        MKSKIPPED = {},
    )

    return state


def RatchetEncrypt(state: State, plaintext: bytes, AD: bytes):
    """ 
    Symmetric key ratchet step + message encryption.
    Returns the header and ciphertext
    """
    state.CKs, mk = kdf.KDF_CK(state.CKs)
    print("Send Ratchet:")
    print(f"    CKs: {state.CKs.hex()}")
    header = create_header(state.DHs, state.PN, state.Ns)
    state.Ns += 1
    return header, aead.encrypt(mk, plaintext, AD + header.encode())


def RatchetDecrypt(state: State, header: Header, ciphertext: bytes, AD: bytes) -> bytes:
    """ Try to decrypt the an incoming message """
    plaintext = TrySkippedMessageKeys(state, header, ciphertext, AD)
    if plaintext is not None:
        return plaintext
    if header.dh != state.DHr:
        print("Performing DH Ratchet")
        # store all skipped keys for current dh ratchet
        SkipMessageKeys(state, header.pn)
        # advance to next dh ratchet
        DHRatchet(state, header)

    # store skipped keys for this ratchet
    SkipMessageKeys(state, header.n)
    state.CKr, mk = kdf.KDF_CK(state.CKr)
    print("Recieve Ratchet:")
    print(f"    CKr: {state.CKr.hex()}")
    state.Nr += 1
    return aead.decrypt(mk, A = AD + header.encode(), C = ciphertext)


def TrySkippedMessageKeys(state: State, header: Header, ciphertext: bytes, AD: bytes):
    """ Try to decrypt using skipped message key if present """
    if (header.dh, header.n) in state.MKSKIPPED:
        mk = state.MKSKIPPED[header.dh, header.n]
        del state.MKSKIPPED[header.dh, header.n]
        return aead.decrypt(mk, A = AD + header.encode(), C = ciphertext)
    else:
        return None


def SkipMessageKeys(state: State, until: int):
    if state.Nr + MAX_SKIP < until:
        raise Exception("Skipped too many message keys")
    if state.CKr != None:
        while state.Nr < until:
            state.CKr, mk = kdf.KDF_CK(state.CKr)
            state.MKSKIPPED[state.DHr, state.Nr] = mk
            state.Nr += 1


def DHRatchet(state: State, header: Header):
    state.PN = state.Ns
    state.Ns = 0
    state.Nr = 0
    state.DHr = header.dh
    state.RK, state.CKr = kdf.KDF_RK(state.RK, x25519.X25519(state.DHs.sk, state.DHr))
    state.DHs = x25519.X25519KeyPair()
    state.RK, state.CKs = kdf.KDF_RK(state.RK, x25519.X25519(state.DHs.sk, state.DHr))
    print("DH Ratchet:")
    print(f"     dh: {x25519.X25519(state.DHs.sk, state.DHr).hex()}")
    print(f"    CKr: {state.CKr.hex()}")
    print(f"    CKs: {state.CKs.hex()}")
