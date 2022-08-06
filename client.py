from dataclasses import dataclass
import datetime
import socket
import threading
import json
from signal_protocol import xed25519, kdf
from signal_protocol.aead import AEAD_AES_128_CBC_HMAC_SHA_256 as aead
from signal_protocol.curve25519 import x25519
from typing import *
from events import Emitter
from enum import Enum
from abc import ABC

APP_INFO = "TestApp"

@dataclass
class Message:
    user_from: str
    message: str
    timestamp: datetime.datetime

    @classmethod
    def from_json(cls, data: dict):
        return cls(
            user_from=data["user_from"],
            message=data["message"],
            timestamp=datetime.datetime.fromisoformat(data["timestamp"])
        )
    
    def to_json(self) -> dict:
        return {
            "user_from": self.user_from,
            "message": self.message,
            "timestamp": self.timestamp.isoformat()
        }


@dataclass
class Conversation:
    username: str
    ik: bytes # Identity public key
    ek: bytes # Ephemeral public key
    opk_id: Optional[str]
    shared_key: bytes
    associated_data: bytes
    other_user_has_key: bool # True if other user has been sent key in any way
    messages: List[Message]

    @classmethod
    def from_json(cls, data: dict):
        return cls(
            username=data["username"],
            ik=bytes.fromhex(data["ik"]),
            ek=bytes.fromhex(data["ek"]),
            opk_id=data["opk_id"],
            shared_key=bytes.fromhex(data["shared_key"]),
            associated_data=bytes.fromhex(data["associated_data"]),
            other_user_has_key=data["other_user_has_key"],
            messages=[Message.from_json(message) for message in data["messages"]]
        )
    
    def to_json(self):
        return {
            "username": self.username,
            "ik": self.ik.hex(),
            "ek": self.ek.hex(),
            "opk_id": self.opk_id,
            "shared_key": self.shared_key.hex(),
            "associated_data": self.associated_data.hex(),
            "other_user_has_key": self.other_user_has_key,
            "messages": [message.to_json() for message in self.messages]
        }


@dataclass
class Session:
    ik: x25519.X25519KeyPair # Identity key
    spk: x25519.X25519KeyPair # Signed prekey
    opks: Dict[int, x25519.X25519KeyPair] # One-time Prekeys
    prekeys_generated: int # keeps track of total prekeys generated ever
    conversations: List[Conversation]
    last_recieved: datetime.datetime

    @classmethod
    def from_json(cls, data: dict):
        return cls(
            ik=x25519.X25519KeyPair.from_json(data["ik"]),
            spk=x25519.X25519KeyPair.from_json(data["spk"]),
            opks={
                k: x25519.X25519KeyPair.from_json(v) for k, v in data["opks"]["keys"].items()
            },
            prekeys_generated=data["opks"]["prekeys_generated"],
            conversations=[Conversation.from_json(conv) for conv in data["conversations"]], # TODO: load conversations
            last_recieved=datetime.datetime.fromisoformat(data["last_recieved"])
        )
    
    def to_json(self) -> dict:
        return {
            "ik": self.ik.to_json(),
            "spk": self.spk.to_json(),
            "opks": {
                "keys": {k: v.to_json() for k, v in self.opks.items()},
                "prekeys_generated": self.prekeys_generated
            },
            "conversations": [conv.to_json() for conv in self.conversations],
            "last_recieved": self.last_recieved.isoformat()
        }
    
    @classmethod
    def create_session(cls, opk_count: int = 10):
        return cls(
            ik=x25519.X25519KeyPair(),
            spk=x25519.X25519KeyPair(),
            opks={str(n): x25519.X25519KeyPair() for n in range(10)},
            prekeys_generated=opk_count,
            conversations=[],
            last_recieved=datetime.datetime.min
        )

class ClientEvent(Enum):
    NEW_CONVERSATION = "NEW_CONVERSATION"
    ON_MESSAGE = "ON_MESSAGE"

class Client(Emitter[ClientEvent]):
    """ Outlines the implementation of an encrypted client """
    
    DATA_LOCATION = "{0}_keys.json"
    
    def __init__(self, username: str):
        super().__init__()
        self.username = username
        self.DATA_FILE = self.DATA_LOCATION.format(username)
        self.server_ip: Optional[str] = None
        self.server_port: Optional[str] = None
        self.socket: Optional[socket.socket] = None

        self.stop_event = threading.Event()
        
        self.session = self.get_session_or_create()
        self.save_session()
        
    def save_session(self):
        with open(self.DATA_FILE, "w") as f:
            json.dump(self.session.to_json(), f, indent=2)
    
    def load_session(self):
        self.session = self.get_session_or_create()
    
    def get_session_or_create(self) -> Session:
        try:
            with open(self.DATA_FILE, "r") as f:
                print("Loaded existing session.")
                return Session.from_json(json.load(f))
        except (OSError, json.JSONDecodeError) as e:
            return Session.create_session()
    
    def connect(self, server_ip: str, server_port: int):
        self.server_ip = server_ip
        self.server_port = server_port

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((server_ip, server_port))

        # send initial packet
        # There is no client authentication, this is just a POC for X3DH
        self.send_packet({
            "type": "client_init",
            "username": self.username,
        })
    
    def publish_keys(self):
        """ Publishes the initial key-set to the server """
        self.send_packet({
            "type": "publish_keys",
            "ik": self.session.ik.pk.hex(),
            "spk": self.session.spk.pk.hex(),
            "prekey_sig": xed25519.sign(self.session.ik.sk, self.session.spk.pk).hex(),
            "opks": {
                identifier: key.pk.hex() for identifier, key in self.session.opks.items()
            }
        })
    
    def update_spk(self):
        # TODO: send new spk to the server
        pass
    
    def publish_more_opks(self):
        # TODO: publish more OPKs when they are needed
        pass

    def request_prekey_bundle(self, other_username: str):
        self.send_packet({
            "type": "get_prekey_bundle",
            "username": other_username
        })

    def establish_shared_key_from_prekey_bundle(self, data: dict):
        """ Establishes a shared key and associated data from a prekey bundle received upon request """
        other_username = data["username"]
        ik_other = bytes.fromhex(data["ik"])
        spk_other = bytes.fromhex(data["spk"])
        prekey_sig = bytes.fromhex(data["prekey_sig"])
        opk_id = data["opk_id"]
        opk = bytes.fromhex(data["opk"]) if data["opk"] else None
        
        # ephemeral key
        ek = x25519.X25519KeyPair()

        # validate prekey_signature
        # TODO: abort if verification fails
        assert xed25519.verify(ik_other, spk_other, prekey_sig) == True

        # we are client a in this case
        # DH1 = DH(IK_a, SPK_b)
        dh1 = x25519.X25519(self.session.ik.sk, spk_other)

        # DH2 = DH(EK_a, IK_b)
        dh2 = x25519.X25519(ek.sk, ik_other)

        # DH3 = DH(EK_a, SPK_b)
        dh3 = x25519.X25519(ek.sk, spk_other)

        combined = dh1 + dh2 + dh3
        
        if opk_id is not None:
            # DH4 = DH(EK_a, OPK_b)
            dh4 = x25519.X25519(ek.sk, opk)
            combined += dh4
        
        shared_key = kdf.KDF(combined, info=APP_INFO.encode("utf-8"))
        associated_data = self.session.ik.pk + ik_other

        print(f"Established shared key with {other_username}: {shared_key.hex()}")
        return shared_key, associated_data, ek.pk
    
    def create_conversation_from_bundle(self, data: dict) -> Conversation:
        """ Initialise a conversation from a prekey bundle """
        SK, AD, EK = self.establish_shared_key_from_prekey_bundle(data)
        other_username = data["username"]
        conv = Conversation(
            username=other_username,
            ik=bytes.fromhex(data["ik"]),
            ek=EK,
            opk_id=data["opk_id"],
            shared_key=SK,
            associated_data=AD,
            other_user_has_key=False,
            messages=[]
        )
        self.session.conversations.append(conv)
        self.dispatch_event(ClientEvent.NEW_CONVERSATION, conv=conv)
        self.save_session()

        return conv
    
    def find_conversation_by_username(self, username: str) -> Optional[Conversation]:
        for conv in self.session.conversations:
            if conv.username == username:
                return conv
        
        return None
    
    def send_message(self, to: str, message: str):
        conv = self.find_conversation_by_username(to)
        if conv is None:
            raise Exception("You have not established a conversation with this user")
        
        shared_key = conv.shared_key
        associated_data = conv.associated_data
        body = aead.encrypt(shared_key, message.encode("utf-8"), associated_data)
        
        message_packet = {
            "type": "message",
            "to": to,
            "body": body.hex(),
        }

        if not conv.other_user_has_key:
            message_packet["initiator"] = {
                "ik": self.session.ik.pk.hex(),
                "ek": conv.ek.hex(),
                "opk_id": conv.opk_id,
            }
            conv.other_user_has_key = True

        self.send_packet(message_packet)

        message_packet["timestamp"] = datetime.datetime.now().isoformat() # TODO: this is hacky

        self.process_message(message_packet, other_user=to)
        self.save_session()
    
    def get_opk_from_id_and_remove(self, opk_id: str) -> Optional[x25519.X25519KeyPair]:
        if opk_id in self.session.opks:
            return self.session.opks.pop(opk_id)
        
        raise Exception(f"Invalid One-time prekey id {opk_id!r}")
    
    def establish_shared_key_from_initiator(self, other_username: str, data: dict):
        """ Establishes a shared key and associated data from an initiator message """
        ik = self.session.ik.sk
        ik_other = bytes.fromhex(data["ik"])
        spk = self.session.spk.sk
        ek = bytes.fromhex(data["ek"])
        opk_id = data["opk_id"]
        if opk_id is None:
            print(f"WARN: communication with {other_username} has no one-time prekey!")
            opk = None
        else:
            opk = self.get_opk_from_id_and_remove(opk_id).sk
            if opk is None:
                raise Exception(f"Could not find one-time prekey of ID {opk_id!r}")

        # we are client b in this case
        # DH1 = DH(IK_a, SPK_b)
        dh1 = x25519.X25519(spk, ik_other)

        # DH2 = DH(EK_a, IK_b)
        dh2 = x25519.X25519(ik, ek)

        # DH3 = DH(EK_a, SPK_b)
        dh3 = x25519.X25519(spk, ek)

        combined = dh1 + dh2 + dh3
        
        if opk_id is not None:
            # DH4 = DH(EK_a, OPK_b)
            dh4 = x25519.X25519(opk, ek)
            combined += dh4
        
        shared_key = kdf.KDF(combined, info=APP_INFO.encode("utf-8"))
        associated_data = ik_other + self.session.ik.pk

        print(f"Established shared key with {other_username}: {shared_key.hex()}")
        return shared_key, associated_data, ek
    
    def create_conversation_from_initiator(self, other_username: str, data: dict) -> Conversation:
        """ Initialise a conversation from an initiator message """
        SK, AD, EK = self.establish_shared_key_from_initiator(other_username, data)
        conv = Conversation(
            username=other_username,
            ik=bytes.fromhex(data["ik"]),
            ek=EK,
            opk_id=data["opk_id"],
            shared_key=SK,
            associated_data=AD,
            other_user_has_key=True, # they sent us initiator, so they must have the key
            messages=[]
        )
        self.session.conversations.append(conv)
        self.dispatch_event(ClientEvent.NEW_CONVERSATION, conv=conv)
        self.save_session()

        return conv
    
    def process_message(self, data: dict, other_user: str):
        user_from = data["from"] if "from" in data else self.username
        conv = self.find_conversation_by_username(other_user)
        if conv is None:
            if "initiator" in data:
                # initialise the convesation
                conv = self.create_conversation_from_initiator(other_user, data["initiator"])
            else:
                raise Exception("Recieved first message without an initialiser")
        
        self.session.last_recieved = datetime.datetime.now()
        
        # process the message
        ciphertext = bytes.fromhex(data["body"])
        text = aead.decrypt(conv.shared_key, conv.associated_data, ciphertext)
        if text is None:
            raise Exception("AEAD failed") # TODO: display warning or something
        
        text = text.decode("utf-8")

        message = Message(
            user_from=user_from,
            message=text,
            timestamp=datetime.datetime.fromisoformat(data["timestamp"])
        )

        conv.messages.append(message)
        self.dispatch_event(ClientEvent.ON_MESSAGE, conv=conv, message=message)
        self.save_session()
    
    def fetch_messages_after(self, timestamp: datetime.datetime):
        self.send_packet({
            "type": "request_messages_after",
            "timestamp": timestamp.isoformat()
        })
    
    def process_messages_after(self, data: dict):
        self.session.last_recieved = datetime.datetime.now()
        self.save_session()
        for username, new_messages in data["messages"].items():
            for message in new_messages:
                self.process_message(message, other_user=username)
    
    def send_packet(self, data):
        # format: length.to_bytes(8, "little") <data>
        if self.socket is None:
            raise Exception("Failed to send packet, socket is None.")
        
        encoded = json.dumps(data).encode("utf-8")
        self.socket.sendall(len(encoded).to_bytes(8, "little") + encoded)

    def recv_packet(self):
        packet_length = int.from_bytes(self.socket.recv(8), "little")
        data = json.loads(self.socket.recv(packet_length).decode("utf-8"))
        return data

    def socket_handler(self):
        try:
            # Fetch message backlog
            self.fetch_messages_after(self.session.last_recieved)
            
            while not self.stop_event.is_set():
                data = self.recv_packet()
                print(f"Received: \n{json.dumps(data, indent=2)}")
                #if data["type"] == "message_forward":
                #    self.receive_message(data)
                if data["type"] == "server_close":
                    print(f"Server closed.")

                elif data["type"] == "disconnect":
                    print(f"Disconnected from server, reason: {data['reason']}")
                
                elif data["type"] == "request_keys":
                    self.publish_keys()

                elif data["type"] == "message":
                    self.process_message(data, other_user=data["from"])

                elif data["type"] == "messages_after":
                    self.process_messages_after(data)
                

                elif data["type"] == "prekey_bundle":
                    self.create_conversation_from_bundle(data)

                else:
                    print(f"Unimplemented message type {data['type']}")

        except Exception as e:
            print("err", repr(e))
            if self.stop_event.is_set():
                print("Disconnected, closing...")
            else:
                print("Lost connection, closing...")
            self.stop_event.set()
