import socket
import threading
import socketserver
import time
from typing import *
from dataclasses import dataclass
import logging
import json

DATETIME_FMT = "%Y-%m-%d %H:%M:%S"
FORMAT = '[%(asctime)s %(levelname)s %(module)s:%(lineno)d] %(message)s'
logging.basicConfig(format=FORMAT, datefmt=DATETIME_FMT, level=logging.INFO)
logger = logging.getLogger('tcp_server')

@dataclass
class Client:
    username: str


def enc_json(data) -> bytes:
    return json.dumps(data).encode("utf-8")


def dec_json(data: bytes):
    return json.loads(data.decode("utf-8"))


def try_send(sock: socket.socket, data) -> bool:
    try:
        sock.send(data)
        return True
    except Exception as e:
        logger.error(f"Exception whilst trying to send data: {e}")
        return False


def recv_all(sock: socket.socket, block_size: int = 1024) -> bytes:
    data = b""
    while True:
        new = sock.recv(block_size)
        data += new
        if len(new) < block_size:
            break

    return data


class Server:
    KEY_FILE = "server_keys.json"

    def __init__(self, sock: socket.socket) -> None:
        self.clients: Dict[socket.socket, Tuple[threading.Thread, Client]] = {}
        self.server_sock = sock
        self.public_keys: Dict[str, int] = {}

        try:
            with open(self.KEY_FILE, "r") as f:
                self.public_keys = json.load(f)

        except (OSError, json.JSONDecodeError):
            pass

    def client_link(self, sock: socket.socket, stop_event: threading.Event):
        """Loop for communicating with a client"""
        while not stop_event.is_set():
            try:
                data = dec_json(recv_all(sock))
                if data["type"] == "message":
                    client = self.clients[sock][1]
                    message = data["message"]
                    self.send_to_all({
                        "type": "message_forward",
                        "name": client.username,
                        "message": message
                    })
                else:
                    logger.error(f"Unimplemented message type {data['type']}")

            except Exception as e:
                logger.error(f"Error from client: {e!r}")
                self.disconnect(sock)
                break

    def disconnect(self, sock: socket.socket):
        client = self.clients[sock][1]
        del self.clients[sock]
        self.send_to_all({
            "type": "user_disconnect",
            "name": client.username
        })

    def send_to_all(self, data):
        d = enc_json(data)
        for s in list(self.clients.keys()):
            success = try_send(s, d)
            if not success:
                self.disconnect(s)

    def list_users(self) -> List[str]:
        return [c.username for _, c in self.clients.values()]

    def loop(self, stop_event: threading.Event):
        logger.info("Server started")
        try:
            while not stop_event.is_set():
                client_socket, client_address = self.server_sock.accept()
                logger.debug("Connection")

                initial_data = dec_json(recv_all(client_socket))
                logger.debug(f"Recieved initial payload: {initial_data}")
                username = initial_data["username"]
                public_key = initial_data["public_key"]
                if username in self.public_keys and self.public_keys[username] != public_key:
                    logger.info(f"Found mismatching key for user {username}")
                    client_socket.send(enc_json({
                        "type": "disconnect",
                        "reason": f"provided public key does not match for user '{username}'"
                    }))
                    continue
                else:
                    self.public_keys[username] = public_key
                    logger.info(f"Saved public key for {username}")
                logger.info(f"{username} @ {client_address[0]}:{client_address[1]} connected.")
                self.send_to_all({
                    "type": "user_connect",
                    "name": username
                })
                client_socket.send(enc_json({
                    "type": "user_list",
                    "users": self.list_users()
                }))

                t = threading.Thread(target=self.client_link, args=(client_socket, stop_event))
                self.clients[client_socket] = t, Client(username)
                t.daemon = True
                t.start()

        except Exception as e:
            logger.error(f"Error on server thread: {e}")
            pass

    def close(self):
        self.send_to_all({"type": "server_close"})
        for s in list(self.clients.keys()):
            thread, client = self.clients[s]
            s.close()
            thread.join()

        self.server_sock.close()
        self.clients.clear()

        with open(self.KEY_FILE, "w") as f:
            json.dump(self.public_keys, f, indent=2)


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
    stop_event = threading.Event()
    t = threading.Thread(target=server.loop, args=(stop_event,))
    t.daemon = True
    t.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Exiting...")
        pass

    stop_event.set()
    server.close()


if __name__ == "__main__":
    main()
