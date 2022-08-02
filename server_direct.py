import contextlib
import os
import socket
import threading
import time
from typing import *
from dataclasses import dataclass
from locked_resource import locked_resource
import datetime
import logging
import json
import uuid

DATETIME_FMT = "%Y-%m-%d %H:%M:%S"
FORMAT = '[%(asctime)s %(levelname)s %(module)s:%(lineno)d] %(message)s'
logging.basicConfig(format=FORMAT, datefmt=DATETIME_FMT, level=logging.DEBUG)
logger = logging.getLogger('tcp_server')


class CloseListener:
    pass


CONVERSATION_FILE = "data/conversations/{0}.json"
USER_FILE = "data/users/{0}.json"

def send_packet(socket, data):
    # format: length.to_bytes(8, "little") <data>
    if socket is None:
        raise Exception("Failed to send packet, socket is None.")
    
    encoded = json.dumps(data).encode("utf-8")
    socket.sendall(len(encoded).to_bytes(8, "little") + encoded)

def recv_packet(socket):
    packet_length = int.from_bytes(socket.recv(8), "little")
    data = json.loads(socket.recv(packet_length).decode("utf-8"))
    return data

def new_conversation_id():
    while True:
        id = str(uuid.uuid4())
        file = CONVERSATION_FILE.format(id)
        if not os.path.exists(file):
            return file


class ClientHandler:
    def __init__(self, server: 'Server', socket: socket.socket, username: str):
        self.server = server
        self.socket = socket
        self.username = username
        self.listener_thread: Optional[threading.Thread] = None
    
    def send_packet(self, data):
        try:
            send_packet(self.socket, data)
        except Exception as e:
            print(f"Exception whilst trying to send packet from {self.username!r}: {e}")
            self.close()


    def recv_packet(self):
        try:
            return recv_packet(self.socket)
        except Exception as e:
            print(f"Exception whilst trying to recieve packet from {self.username!r}: {e}")
            self.close()
            return CloseListener()
    
    def listener(self):
        user_data = self.server.get_user(self.username)
        if user_data["keys"] is None:
            self.send_packet({"type": "request_keys"})

        while not self.server.stop_event.is_set():
            data = self.recv_packet()
            print(f"Recieved packet: {data}")

            if isinstance(data, CloseListener):
                return

            if data["type"] == "message":
                self.process_message(data)
            
            elif data["type"] == "publish_keys":
                self.store_published_keys(data)

            elif data["type"] == "get_prekey_bundle":
                self.fetch_prekey_bundle(data)
            
            elif data["type"] == "request_messages_after":
                self.send_messages_after(datetime.datetime.fromisoformat(data["timestamp"]))
            
            else:
                print(f"Unkown packet type {data['type']!r}")
    
    def process_message(self, data):
        timestamp = datetime.datetime.now().isoformat()
        with self.server.user(self.username) as user_data:
            user_data = self.server.get_user(self.username)
            if data["to"] not in user_data["conversations"]:
                user_data["conversations"][data["to"]] = str(uuid.uuid4())
            
            conversation_id = user_data["conversations"][data["to"]]
            self.server.save_user(self.username, user_data)
        
        with self.server.user(data["to"]) as other_user_data:
            if self.username not in other_user_data["conversations"]:
                other_user_data["conversations"][self.username] = conversation_id
            
            self.server.save_user(data["to"], other_user_data)

            
        with self.server.conversation(conversation_id) as conv:
            conv["messages"].append({
                **data,
                "type": "message",
                "from": self.username,
                "timestamp": timestamp,
            })
            self.server.save_conversation(conversation_id, conv)
    
        if data["to"] in self.server.clients:
            data["from"] = self.username
            data["timestamp"] = timestamp
            self.server.clients[data["to"]].send_packet(data)
    
    def send_messages_after(self, timestamp: datetime.datetime):
        missed = {}
        user_data = self.server.get_user(self.username)
        for username, conv_id in user_data["conversations"].items():
            conv = self.server.get_conversation(conv_id)
            missed[username] = [
                message
                for message in conv["messages"]
                if datetime.datetime.fromisoformat(message["timestamp"]) > timestamp
            ]
        
        print(f"Sending backlog:\n{json.dumps(missed, indent=2)}")
        
        self.send_packet({
            "type": "messages_after",
            "messages": missed
        })
    
    def store_published_keys(self, data):
        with self.server.user(self.username) as user:
            assert user["keys"] is None
            user["keys"] = {
                "ik": data["ik"],
                "spk": data["spk"],
                "prekey_sig": data["prekey_sig"],
                "opks": data["opks"]
            }
            self.server.save_user(self.username, user)
            print(f"Saved keys for {self.username}")
    
    def fetch_prekey_bundle(self, data):
        username = data["username"]
        with self.server.user(username) as user:
            # get one-time prekey if available
            opk_id = None
            opk = None
            if len(user["keys"]["opks"]) > 0:
                opk_id = list(user["keys"]["opks"].keys())[0]
                opk = user["keys"]["opks"].pop(opk_id)

                print(f"Removed one-time prekey {opk_id} from {username}")
            
            ik = user["keys"]["ik"]
            spk = user["keys"]["spk"]
            prekey_sig = user["keys"]["prekey_sig"]
            
            self.server.save_user(username, user)
        
        self.send_packet({
            "type": "prekey_bundle",
            "username": username,
            "ik": ik,
            "spk": spk,
            "prekey_sig": prekey_sig,
            "opk_id": opk_id,
            "opk": opk
        })
    
    def close(self):
        with locked_resource("__clients__"):
            self.socket.close()
            self.server.clients.pop(self.username)


class Server:
    KEY_FILE = "server_keys.json"

    def __init__(self, sock: socket.socket) -> None:
        self.clients: Dict[str, ClientHandler] = {}
        self.server_sock = sock
        self.stop_event = threading.Event() # TODO

        try:
            with open(self.KEY_FILE, "r") as f:
                self.public_keys = json.load(f)

        except (OSError, json.JSONDecodeError):
            pass
    
    def get_conversation(self, id: str):
        file = CONVERSATION_FILE.format(id)
        if not os.path.exists(file):
            return {"messages": []}
        else:
            with open(file, "r") as f:
                return json.load(f)
    
    def save_conversation(self, id: str, data):
        file = CONVERSATION_FILE.format(id)
        with open(file, "w") as f:
            json.dump(data, f, indent=2)
    
    @contextlib.contextmanager
    def conversation(self, id: str):
        file = CONVERSATION_FILE.format(id)
        with locked_resource(file): # TODO: hate this hacky thing
            yield self.get_conversation(id)

    def get_user(self, username: str):
        file = USER_FILE.format(username)
        if not os.path.exists(file):
            return {
                "username": username,
                "keys": None,
                "conversations": {}
            }
        else:
            with open(file, "r") as f:
                return json.load(f)

    def save_user(self, username: str, data: dict):
        file = USER_FILE.format(username)
        with open(file, "w") as f:
            json.dump(data, f, indent=2)
    
    @contextlib.contextmanager
    def user(self, username: str):
        file = USER_FILE.format(username)
        with locked_resource(file): # TODO: hate this hacky thing
            yield self.get_user(username)

    def loop(self):
        logger.info("Server started")
        try:
            while not self.stop_event.is_set():
                client_socket, client_address = self.server_sock.accept()
                logger.debug("Connection")

                initial_data = recv_packet(client_socket)
                logger.debug(f"Recieved initial payload: {initial_data}")
                username = initial_data["username"]

                logger.info(f"{username} @ {client_address[0]}:{client_address[1]} connected.")
                
                client = ClientHandler(server=self, socket=client_socket, username=username)
                t = threading.Thread(target=client.listener)
                client.listener_thread = t # TODO: listener should capture thread itself
                self.clients[username] = client
                t.daemon = True
                t.start()

        except Exception as e:
            logger.error(f"Error on server thread: {e}")
            pass

    def close(self):
        self.stop_event.set()
        for client in self.clients.values():
            client.send_packet({"type": "server_close"})
            client.close()
        
        self.clients.clear()
        self.server_sock.close()


def main():
    HOST = socket.gethostbyname(socket.gethostname())
    PORT = 6777

    logger.info(f"Setting up for hosting at {HOST}:{PORT}")

    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(5)

    server = Server(s)

    # Server thread
    t = threading.Thread(target=server.loop)
    t.daemon = True
    t.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Exiting...")
        pass

    server.stop_event.set()
    server.close()


if __name__ == "__main__":
    main()