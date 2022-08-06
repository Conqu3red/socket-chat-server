from dataclasses import dataclass
from .curve25519 import x25519
from . import xed25519, kdf
from typing import Dict, Optional, Tuple, List


@dataclass
class GlobalState:
    ik: x25519.X25519KeyPair # Identity key
    spk: x25519.X25519KeyPair # Signed prekey
    opks: Dict[str, x25519.X25519KeyPair] # One-time Prekeys
    prekeys_generated: int # keeps track of total prekeys generated ever

    @classmethod
    def from_json(cls, data: dict):
        return cls(
            ik=x25519.X25519KeyPair.from_json(data["ik"]),
            spk=x25519.X25519KeyPair.from_json(data["spk"]),
            opks={
                k: x25519.X25519KeyPair.from_json(v) for k, v in data["opks"]["keys"].items()
            },
            prekeys_generated=data["opks"]["prekeys_generated"]
        )
    
    def to_json(self) -> dict:
        return {
            "ik": self.ik.to_json(),
            "spk": self.spk.to_json(),
            "opks": {
                "keys": {k: v.to_json() for k, v in self.opks.items()},
                "prekeys_generated": self.prekeys_generated
            },
        }
    
    @classmethod
    def create(cls, opk_count: int = 10):
        return cls(
            ik=x25519.X25519KeyPair(),
            spk=x25519.X25519KeyPair(),
            opks={str(n): x25519.X25519KeyPair() for n in range(10)},
            prekeys_generated=opk_count
        )
    
    def get_opk_from_id_and_remove(self, opk_id: str):
        if opk_id in self.opks:
            return self.opks.pop(opk_id)
        
        raise Exception(f"Invalid One-time prekey id {opk_id!r}")


@dataclass
class ProtocolState:
    other_ik: bytes
    ek: bytes
    opk_id: Optional[str]
    associated_data: bytes
    received_response: bool # True if other user has been sent key in any way

    @classmethod
    def from_json(cls, data: dict):
        return cls(
            other_ik=bytes.fromhex(data["other_ik"]),
            ek=bytes.fromhex(data["ek"]),
            opk_id=data["opk_id"],
            associated_data=bytes.fromhex(data["associated_data"]),
            received_response=data["received_response"]
        )
    
    def to_json(self):
        return {
            "other_ik": self.other_ik.hex(),
            "ek": self.ek.hex(),
            "opk_id": self.opk_id,
            "associated_data": self.associated_data.hex(),
            "received_response": self.received_response
        }


@dataclass
class KeyPublishingBundle:
    ik: bytes
    spk: bytes
    prekey_sig: bytes
    opks: Dict[str, bytes]

    @classmethod
    def from_json(cls, data: dict):
        return cls(
            ik=bytes.fromhex(data["ik"]),
            spk=bytes.fromhex(data["spk"]),
            prekey_sig=bytes.fromhex(data["prekey_sig"]),
            opks={ident: bytes.fromhex(pk) for ident, pk in data["opks"].items()}
        )
    
    def to_json(self):
        return {
            "ik": self.ik.hex(),
            "spk": self.spk.hex(),
            "prekey_sig": self.prekey_sig.hex(),
            "opks": {ident: pk.hex() for ident, pk in self.opks.items()}
        }


def create_key_publishing_bundle(state: GlobalState):
    return KeyPublishingBundle(
        ik=state.ik.pk,
        spk=state.spk.pk,
        prekey_sig=xed25519.sign(state.ik.sk, state.spk.pk),
        opks={
            ident: key.pk for ident, key in state.opks.items()
        }
    )


@dataclass
class PrekeyBundle:
    ik: bytes # public key part
    spk: bytes # public key part
    prekey_sig: bytes
    opk_id: Optional[str]
    opk: Optional[bytes] # optional public key part

    @classmethod
    def from_json(cls, data: dict):
        opk = data.get("opk")
        if opk is not None:
            opk = bytes.fromhex(opk)
        return cls(
            ik=bytes.fromhex(data["ik"]),
            spk=bytes.fromhex(data["spk"]),
            prekey_sig=bytes.fromhex(data["prekey_sig"]),
            opk_id=data.get("opk_id"),
            opk=opk
        )
    
    def to_json(self):
        data = {
            "ik": self.ik.hex(),
            "spk": self.spk.hex(),
            "prekey_sig": self.prekey_sig.hex(),
            "opk_id": self.opk_id
        }

        if self.opk is not None:
            data["opk"] = self.opk.hex()
        
        return data


@dataclass
class InitiatorBundle:
    ik: bytes
    ek: bytes
    opk_id: Optional[str]

    @classmethod
    def from_json(cls, data: dict):
        return cls(
            ik=bytes.fromhex(data["ik"]),
            ek=bytes.fromhex(data["ek"]),
            opk_id=data.get("opk_id"),
        )

    def to_json(self):
        return {
            "ik": self.ik.hex(),
            "ek": self.ek.hex(),
            "opk_id": self.opk_id
        }


def establish_protocol_state_from_bundle(state: GlobalState, bundle: PrekeyBundle, APP_INFO: str) -> Tuple[bytes, ProtocolState]:
    """
    Establish a shared key from a prekey bundle
    Returns a tuple containing the established shared key (SK) and a `ProtocolState` instance
    """
    
    # ephemeral key
    ek = x25519.X25519KeyPair()

    # validate prekey_signature
    # TODO: abort if verification fails
    assert xed25519.verify(bundle.ik, bundle.spk, bundle.prekey_sig) == True, "prekey signature is invalid"

    # we are client a in this case
    # DH1 = DH(IK_a, SPK_b)
    dh1 = x25519.X25519(state.ik.sk, bundle.spk)

    # DH2 = DH(EK_a, IK_b)
    dh2 = x25519.X25519(ek.sk, bundle.ik)

    # DH3 = DH(EK_a, SPK_b)
    dh3 = x25519.X25519(ek.sk, bundle.spk)

    combined = dh1 + dh2 + dh3
    
    if bundle.opk_id is not None:
        # DH4 = DH(EK_a, OPK_b)
        dh4 = x25519.X25519(ek.sk, bundle.opk)
        combined += dh4
    
    shared_key = kdf.KDF(combined, info=APP_INFO.encode("utf-8"))
    associated_data = state.ik.pk + bundle.ik

    protocol_state = ProtocolState(
        other_ik=bundle.ik,
        ek=ek.pk,
        opk_id=bundle.opk_id,
        associated_data=associated_data,
        received_response=False
    )

    return shared_key, protocol_state


def establish_protocol_state_from_initiator(state: GlobalState, initiator: InitiatorBundle, APP_INFO: str) -> Tuple[bytes, ProtocolState]:
    """
    Establish a shared key from an initiator bundle included in a received message
    Returns a tuple containing the established shared key (SK) and a `ProtocolState` instance
    """
    if initiator.opk_id is None:
        print(f"WARN: initiator has no one-time prekey!")
        opk = None
    else:
        opk = state.get_opk_from_id_and_remove(initiator.opk_id)

    # we are client b in this case
    # DH1 = DH(IK_a, SPK_b)
    dh1 = x25519.X25519(state.spk.sk, initiator.ik)

    # DH2 = DH(EK_a, IK_b)
    dh2 = x25519.X25519(state.ik.sk, initiator.ek)

    # DH3 = DH(EK_a, SPK_b)
    dh3 = x25519.X25519(state.spk.sk, initiator.ek)

    combined = dh1 + dh2 + dh3
    
    if opk is not None:
        # DH4 = DH(EK_a, OPK_b)
        dh4 = x25519.X25519(opk.sk, initiator.ek)
        combined += dh4
    
    shared_key = kdf.KDF(combined, info=APP_INFO.encode("utf-8"))
    associated_data = initiator.ik + state.ik.pk

    #print(f"Established shared key with {other_username}: {shared_key.hex()}")
    
    protocol_state = ProtocolState(
        other_ik=initiator.ik,
        ek=initiator.ek,
        opk_id=initiator.opk_id,
        associated_data=associated_data,
        received_response=True
    )

    return shared_key, protocol_state
