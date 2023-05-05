from dataclasses import dataclass
import datetime
import socket
import threading
import json
from signal_protocol import double_ratchet, x3dh
from typing import *
from events import Emitter
from enum import Enum
import traceback
from socket_utils import *

DATETIME_FMT = "%Y-%m-%d %H:%M:%S"
FORMAT = '%(asctime)s %(module)s:%(lineno)d %(name)s[%(process)d] %(levelname)s %(message)s'

try:
    import coloredlogs
    coloredlogs.install(fmt=FORMAT, datefmt=DATETIME_FMT, level=logging.DEBUG)
except ImportError:
    logging.basicConfig(format=FORMAT, datefmt=DATETIME_FMT, level=logging.DEBUG)

logger = logging.getLogger('client')

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
    x3dh_state: x3dh.ProtocolState
    ratchet_state: double_ratchet.State
    messages: List[Message]

    @classmethod
    def from_json(cls, data: dict):
        return cls(
            username=data["username"],
            x3dh_state=x3dh.ProtocolState.from_json(data["x3dh_state"]),
            ratchet_state=double_ratchet.State.from_json(data["ratchet_state"]),
            messages=[Message.from_json(message) for message in data["messages"]]
        )
    
    def to_json(self):
        return {
            "username": self.username,
            "x3dh_state": self.x3dh_state.to_json(),
            "ratchet_state": self.ratchet_state.to_json(),
            "messages": [message.to_json() for message in self.messages]
        }


@dataclass
class Session:
    state: x3dh.GlobalState
    conversations: List[Conversation]
    last_recieved: datetime.datetime

    @classmethod
    def from_json(cls, data: dict):
        return cls(
            state=x3dh.GlobalState.from_json(data["state"]),
            conversations=[Conversation.from_json(conv) for conv in data["conversations"]], # TODO: load conversations
            last_recieved=datetime.datetime.fromisoformat(data["last_recieved"])
        )
    
    def to_json(self) -> dict:
        return {
            "state": self.state.to_json(),
            "conversations": [conv.to_json() for conv in self.conversations],
            "last_recieved": self.last_recieved.isoformat()
        }
    
    @classmethod
    def create_session(cls, opk_count: int = 10):
        return cls(
            state=x3dh.GlobalState.create(opk_count=opk_count),
            conversations=[],
            last_recieved=datetime.datetime.min
        )


class ClientEvent(Enum):
    NEW_CONVERSATION = "NEW_CONVERSATION"
    ON_MESSAGE = "ON_MESSAGE"
    ON_CLOSE = "ON_CLOSE"


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
                logger.info("Loaded existing session.")
                return Session.from_json(json.load(f))
        except (OSError, json.JSONDecodeError) as e:
            return Session.create_session()
    
    def connect(self, server_ip: str, server_port: int):
        self.server_ip = server_ip
        self.server_port = server_port

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((server_ip, server_port))
        self.socket.setblocking(False) # after connection

        # send initial packet
        # There is no client authentication, this is just a POC for X3DH
        self.send_packet({
            "type": "client_init",
            "username": self.username,
        })
    
    def publish_keys(self):
        """ Publishes the initial key-set to the server """
        key_publish_data = x3dh.create_key_publishing_bundle(self.session.state)
        self.send_packet({
            "type": "publish_keys",
            **key_publish_data.to_json()
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
    
    def create_conversation_from_bundle(self, data: dict) -> Conversation:
        """ Initialise a conversation from a prekey bundle """
        prekey_bundle = x3dh.PrekeyBundle.from_json(data)
        SK, protocol_state = x3dh.establish_protocol_state_from_bundle(
            state=self.session.state,
            bundle=prekey_bundle,
            APP_INFO=APP_INFO
        )
        other_username = data["username"]
        conv = Conversation(
            username=other_username,
            x3dh_state=protocol_state,
            ratchet_state = double_ratchet.ratchetInitAsFirstSender(
                SK=SK,
                other_dh_public_key=prekey_bundle.spk
            ),
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
        
        header, body = double_ratchet.RatchetEncrypt(
            state = conv.ratchet_state,
            plaintext = message.encode("utf-8"),
            AD = conv.x3dh_state.associated_data
        )
        
        message_packet = {
            "type": "message",
            "to": to,
            "header": header.encode().hex(),
            "body": body.hex(),
        }

        if not conv.x3dh_state.received_response:
            initiator = x3dh.InitiatorBundle(
                ik=self.session.state.ik.pk,
                ek=conv.x3dh_state.ek,
                opk_id=conv.x3dh_state.opk_id
            )
            message_packet["initiator"] = initiator.to_json()
            

        self.send_packet(message_packet)

        message_packet["timestamp"] = datetime.datetime.now().isoformat() # TODO: this is hacky

        # we sent the message, so we just add the plain one
        self.add_message(
            conv,
            Message(
                user_from=self.username,
                message=message,
                timestamp=datetime.datetime.now()
            )
        )
        self.save_session()
    
    def create_conversation_from_initiator(self, other_username: str, data: dict) -> Conversation:
        """ Initialise a conversation from an initiator message """
        initiator = x3dh.InitiatorBundle.from_json(data)
        SK, protocol_bundle = x3dh.establish_protocol_state_from_initiator(
            state=self.session.state,
            initiator=initiator,
            APP_INFO=APP_INFO
        )
        conv = Conversation(
            username=other_username,
            x3dh_state=protocol_bundle,
            ratchet_state = double_ratchet.ratchetInitAsFirstReciever(
                SK=SK,
                dh_key_pair=self.session.state.spk
            ),
            messages=[]
        )
        self.session.conversations.append(conv)
        self.dispatch_event(ClientEvent.NEW_CONVERSATION, conv=conv)
        self.save_session()

        return conv
    
    def add_message(self, conv: Conversation, message: Message):
        conv.messages.append(message)
        self.dispatch_event(ClientEvent.ON_MESSAGE, conv=conv, message=message)
        self.save_session()
    
    def process_message(self, data: dict, other_user: str):
        user_from = data["from"]
        conv = self.find_conversation_by_username(other_user)
        if conv is None:
            if "initiator" in data:
                # initialise the convesation
                conv = self.create_conversation_from_initiator(other_user, data["initiator"])
            else:
                raise Exception("Recieved first message without an initialiser")
        
        self.session.last_recieved = datetime.datetime.now()

        if conv.x3dh_state.received_response == False:
            conv.x3dh_state.received_response = True
        
        # process the message
        header = double_ratchet.Header.decode(bytes.fromhex(data["header"]))
        ciphertext = bytes.fromhex(data["body"])
        raw_text = double_ratchet.RatchetDecrypt(conv.ratchet_state, header, ciphertext, conv.x3dh_state.associated_data)
        
        if raw_text is None:
            raise Exception("Ratchet Decryption failed, message may have been tampered with.") # TODO: display warning or something
        
        text = raw_text.decode("utf-8")

        # TODO: put message into correct place
        # need to tie order to messages incase they are recieved incorrectly
        message = Message(
            user_from=user_from,
            message=text,
            timestamp=datetime.datetime.fromisoformat(data["timestamp"])
        )

        self.add_message(conv, message)
    
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
                if message["from"] != self.username:
                    self.process_message(message, other_user=username)
                else:
                    logger.error("Received a message from ourselves so cannot decrypt")
    
    def send_packet(self, data):
        send_packet(self.socket, data)

    def recv_packet(self):
        try:
            return recv_packet(self.socket)
        except Exception as e:
            if not self.stop_event.is_set():
                logger.critical(f"Exception whilst trying to recieve packet: {e}")
                self.stop_event.set()
            
            raise ClosedSocket()

    def socket_handler(self):
        try:
            # Fetch message backlog
            self.fetch_messages_after(self.session.last_recieved)
            
            while not self.stop_event.is_set():
                try:
                    data = self.recv_packet()
                except ClosedSocket:
                    logger.info(f"Connection closed, Exiting...")
                    break
                
                logger.debug(f"Received: \n{json.dumps(data, indent=2)}")
                #if data["type"] == "message_forward":
                #    self.receive_message(data)

                if data["type"] == "disconnect":
                    logger.info(f"Disconnected from server, reason: {data['reason']}")
                
                elif data["type"] == "request_keys":
                    self.publish_keys()

                elif data["type"] == "message":
                    self.process_message(data, other_user=data["from"])

                elif data["type"] == "messages_after":
                    self.process_messages_after(data)
                

                elif data["type"] == "prekey_bundle":
                    self.create_conversation_from_bundle(data)

                else:
                    logger.critical(f"Unimplemented message type {data['type']}")

        except Exception as e:
            logger.critical("err", repr(e))
            traceback.print_exc()
            if self.stop_event.is_set():
                logger.info("Disconnected, closing...")
            else:
                logger.info("Lost connection, closing...")
            self.stop_event.set()

        finally:
            self.dispatch_event(ClientEvent.ON_CLOSE)
