import os
import socket
import select
import errno
import threading
import time
from typing import *
import datetime
import logging
import json
import uuid
import traceback
import sqlite3
from dataclasses import dataclass
import coloredlogs

DATETIME_FMT = "%Y-%m-%d %H:%M:%S"
FORMAT = '%(asctime)s %(module)s:%(lineno)d %(name)s[%(process)d] %(levelname)s %(message)s'
coloredlogs.install(fmt=FORMAT, datefmt=DATETIME_FMT, level=logging.DEBUG)
logger = logging.getLogger('tcp_server')

DATABASE = "server_db.db"

class Db:
    def __init__(self, database: str):
        self.con = sqlite3.connect(database)

    @dataclass
    class User:
        id: int
        name: str
        IK_P: str
        SPK_P: str
        SPK_SIG: str
    
    @dataclass
    class Opk:
        user_id: int
        opk_id: int
        value: str
    
    @dataclass
    class Conversation:
        id: int
        user1_id: int
        user2_id: int
    
    @dataclass
    class Message:
        id: int
        conversation_id: int
        sender_id: int
        timestamp: int
        body: str

    def db_init(self):
        
        self.con.execute("""
        CREATE TABLE IF NOT EXISTS user(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            IK_P TEXT NOT NULL,
            SPK_P TEXT NOT NULL,
            SPK_SIG TEXT NOT NULL
        );
        """)

        
        self.con.execute("""
        CREATE TABLE IF NOT EXISTS opk(
            user_id INTEGER NOT NULL,
            opk_id INTEGER NOT NULL,
            value TEXT NOT NULL,
            PRIMARY KEY (user_id, opk_id),
            FOREIGN KEY (user_id) REFERENCES user(id)
        );
        """)

        
        self.con.execute("""
        CREATE TABLE IF NOT EXISTS conversation(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user1_id INTEGER NOT NULL,
            user2_id INTEGER NOT NULL,
            FOREIGN KEY (user1_id) REFERENCES user(id)
            FOREIGN KEY (user2_id) REFERENCES user(id)
        );
        """)

        
        self.con.execute("""
        CREATE TABLE IF NOT EXISTS message(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id INTEGER NOT NULL,
            sender_id INTEGER NOT NULL,
            timestamp INTEGER NOT NULL,
            body TEXT NOT NULL,
            FOREIGN KEY (conversation_id) REFERENCES conversation(id)
            FOREIGN KEY (sender_id) REFERENCES user(id)
        );
        """)
        
    def commit(self):
        self.con.commit()
    
    def close(self):
        self.commit()
        self.con.close()


    def user_create(self, name: str, IK_P: str, SPK_P: str, SPK_SIG: str):
        
        res = self.con.execute("""
        INSERT INTO user(name, IK_P, SPK_P, SPK_SIG)
        VALUES (?, ?, ?, ?)
        RETURNING id;
        """, (name, IK_P, SPK_P, SPK_SIG))
        id = res.fetchone()[0]
        return id


    def user_select_by_id(self, id: str):
        res = self.con.execute("SELECT * FROM user WHERE id = ?;", (id,))
        r = res.fetchone()
        return None if not r else self.User(r[0], r[1], r[2], r[3], r[4])
    
    def user_select_by_name(self, name: str):
        res = self.con.execute("SELECT * FROM user WHERE name = ?;", (name,))
        r = res.fetchone()
        return None if not r else self.User(r[0], r[1], r[2], r[3], r[4])


    def opk_insert(self, user_id: int, opk_id: int, value: str):
        
        self.con.execute("""
        INSERT INTO opk(user_id, opk_id, value)
        VALUES (?, ?, ?)
        """, (user_id, opk_id, value))
        

    #def get_opks(self, user_id: int):
    #    
    #    res = self.con.execute("""
    #    SELECT opk_id, value FROM opk
    #    WHERE user_id = ?;
    #    """, (user_id,))
    #    r = res.fetchall()
    #        #    return r
    
    def get_opk(self, user_id: int):
        res = self.con.execute("""
        SELECT * FROM opk
        WHERE user_id = ?
        LIMIT 1;
        """, (user_id,))
        r = res.fetchone()
        return None if not r else self.Opk(r[0], r[1], r[2])


    def del_opk(self, user_id: int, opk_id: int):
        self.con.execute("""
        DELETE FROM opk
        WHERE user_id = ? AND opk_id = ?
        """, (user_id, opk_id))
        

    def conv_create(self, user1_id: str, user2_id: str):
        res = self.con.execute("""
        INSERT INTO conversation(user1_id, user2_id)
        VALUES (?, ?)
        RETURNING id
        """, (user1_id, user2_id))
        r = res.fetchone()[0]
        return r
    
    def conv_select(self, user1_id: str, user2_id: str):
        res = self.con.execute("""
        SELECT * FROM conversation
        WHERE (user1_id = :i1 AND user2_id = :i2) OR (user1_id = :i2 AND user2_id = :i1)
        """, {"i1": user1_id, "i2": user2_id})
        r = res.fetchone()
        return None if not r else self.Conversation(*r)


    def conv_select_all(self, user_id: str):
        res = self.con.execute("""
        SELECT * FROM conversation
        WHERE user1_id = :i1 OR user2_id = :i1;
        """, {"i1": user_id})
        r = res.fetchall()
        return None if not r else [self.Conversation(*c) for c in r]


    def message_insert(self, conversation_id: int, sender_id: int, timestamp: int, body: str):
        
        self.con.execute("""
        INSERT INTO message(conversation_id, sender_id, timestamp, body)
        VALUES (?, ?, ?, ?)
        """, (conversation_id, sender_id, timestamp, body))
        
    def message_select_new(self, conversation_id: int, timestamp: int):
        
        res = self.con.execute("""
        SELECT * FROM message
        WHERE conversation_id = ? AND timestamp > ?
        ORDER BY timestamp ASC;
        """, (conversation_id, timestamp))
        messages = res.fetchall()
        return [self.Message(*m) for m in messages]


class ClosedSocket(Exception):
    pass


CONVERSATION_FILE = "data/conversations/{0}.json"
USER_FILE = "data/users/{0}.json"

def send_packet(sock: socket.socket, data):
    # format: length.to_bytes(8, "little") <data>
    if sock is None:
        raise Exception("Failed to send packet, socket is None.")
    
    encoded = json.dumps(data).encode("utf-8")
    content = len(encoded).to_bytes(8, "little") + encoded
    data_size = len(content)

    logger.debug(f"Send: Sending {data_size} bytes")
    
    total_sent = 0
    while len(content):
        try:
            sent = sock.send(content)
            total_sent += sent
            content = content[sent:]
            logger.debug(f"Send: Sent {sent} bytes")
        except OSError as e:
            if e.errno != socket.EAGAIN and e.errno != socket.EWOULDBLOCK:
                raise e
            logger.debug(f"Send: Blocking, {len(content)} bytes remaining...")
            r, w, x = select.select([], [sock], [sock]) # TODO: timeout
            if x:
                logger.debug("ERR", x)
    
    assert total_sent == data_size


def recv_data(sock: socket.socket, length: int):
    data = b""
    bytes_left = length
    logger.debug(f"Recv: Expecting {length} bytes")
    while bytes_left > 0:
        try:
            recieved = sock.recv(bytes_left)
            bytes_left -= len(recieved)
            data += recieved
            logger.debug(f"Recv: Recieved {len(recieved)} bytes")
        except OSError as e:
            if e.errno != socket.EAGAIN and e.errno != socket.EWOULDBLOCK:
                raise e
            logger.debug(f"Recv: Blocking, {bytes_left} bytes remaining...")
            r, w, x = select.select([sock], [], [sock])
            if x:
                logger.debug("ERR", x)
    
    return data


def recv_packet(sock: socket.socket):
    packet_length = int.from_bytes(recv_data(sock, 8), "little")
    data = json.loads(recv_data(sock, packet_length).decode("utf-8"))
    return data


def sock_accept(sock: socket.socket):
    logger.debug(f"Accept: Waiting")
    while True:
        try:
            client_sock, addr = sock.accept()
            logger.debug(f"Accept: Recieved connection {addr}")
            yield client_sock, addr
        except OSError as e:
            if e.errno != socket.EAGAIN and e.errno != socket.EWOULDBLOCK:
                raise e
        
            logger.debug(f"Accept: Blocking")
            r, w, x = select.select([sock], [sock], [sock])
            if x:
                logger.debug("ERR", x)


class ClientHandler:
    def __init__(self, server: 'Server', socket: socket.socket, username: str):
        self.server = server
        self.socket = socket
        self.username = username
        self.listener_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.closed = False
    
    def send_packet(self, data):
        try:
            send_packet(self.socket, data)
        except Exception as e:
            if not self.stop_event.is_set():
                logger.critical(f"Exception whilst trying to send packet from {self.username!r}: {e}")
                self.close()

    def recv_packet(self):
        try:
            return recv_packet(self.socket)
        except Exception as e:
            if not self.stop_event.is_set():
                logger.critical(f"Exception whilst trying to recieve packet from {self.username!r}: {e}")
                self.close()
            
            raise ClosedSocket()
    
    def listener(self):
        self.db = Db(DATABASE)
        user = self.db.user_select_by_name(self.username)
        if user is None:
            self.send_packet({"type": "request_keys"})

        while not self.server.stop_event.is_set() and not self.stop_event.is_set():
            try:
                data = self.recv_packet()
            except ClosedSocket:
                return
            
            logger.debug(f"({self.username}) sent packet: \n{json.dumps(data, indent=2)}")

            if data["type"] == "message":
                self.process_message(data)
            
            elif data["type"] == "publish_keys":
                self.store_published_keys(data)

            elif data["type"] == "get_prekey_bundle":
                self.fetch_prekey_bundle(data)
            
            elif data["type"] == "request_messages_after":
                self.send_messages_after(datetime.datetime.fromisoformat(data["timestamp"]))
            
            else:
                logger.critical(f"Unkown packet type {data['type']!r}")
    
    def process_message(self, data):
        timestamp = int(time.time())
        user_data = self.db.user_select_by_name(self.username)
        other_user_data = self.db.user_select_by_name(data["to"])

        conv = self.db.conv_select(user_data.id, other_user_data.id)
        if conv is None:
            self.db.conv_create(user_data.id, other_user_data.id)
            self.db.commit()
            conv = self.db.conv_select(user_data.id, other_user_data.id)
            logger.info(f"Created conversation between {self.username} and {other_user_data.name}")
        
        body = {}
        for key in ("intitiator", "header", "body"):
            if key in data:
                body[key] = data[key]
        
        self.db.message_insert(conv.id, user_data.id, timestamp, json.dumps(body))
        self.db.commit()
    
        if data["to"] in self.server.clients:
            data["from"] = self.username
            data["timestamp"] = datetime.datetime.fromtimestamp(timestamp).isoformat()
            self.server.clients[data["to"]].send_packet(data)
    
    def send_messages_after(self, timestamp: datetime.datetime):
        missed = {}
        user_data = self.db.user_select_by_name(self.username)
        if user_data is not None:
            conversations = self.db.conv_select_all(user_data.id)

            for conv in conversations:
                new_messages = self.db.message_select_new(conv.id, int(timestamp.timestamp()))
                if len(new_messages) > 0:
                    other_user_data = self.db.user_select_by_id(conv.user1_id if conv.user1_id != user_data.id else conv.user2_id)
                    missed[other_user_data.name] = [
                        {
                            "to": other_user_data.name if user_data.id == m.sender_id else user_data.name,
                            "from": user_data.name if user_data.id == m.sender_id else other_user_data.name,
                            "timestamp": datetime.datetime.fromtimestamp(m.timestamp).isoformat(),
                            **json.loads(m.body)
                        } for m in new_messages if m.sender_id != user_data.id # send only other users messages
                    ]
                    # TODO: send all messages and have client distinguish
        
        logger.debug(f"Sending backlog:\n{json.dumps(missed, indent=2)}")
        
        self.send_packet({
            "type": "messages_after",
            "messages": missed
        })
    
    def store_published_keys(self, data):
        user_id = self.db.user_create(self.username, data["ik"], data["spk"], data["prekey_sig"])
        for id, val in data["opks"].items():
            self.db.opk_insert(user_id, int(id), val)
        self.db.commit()
        logger.info(f"Saved keys for {self.username}")
    
    def fetch_prekey_bundle(self, data):
        username = data["username"]
        user_data = self.db.user_select_by_name(username)
        if user_data is None:
            return # TODO: send not found response

        # get one-time prekey if available
        opk = self.db.get_opk(user_data.id)
        if opk is not None:
            self.db.del_opk(user_data.id, opk.opk_id)
            self.db.commit()
            logger.info(f"Removed one-time prekey {opk.opk_id} from {username}")
        
        self.send_packet({
            "type": "prekey_bundle",
            "username": username,
            "ik": user_data.IK_P,
            "spk": user_data.SPK_P,
            "prekey_sig": user_data.SPK_SIG,
            "opk_id": str(opk.opk_id),
            "opk": opk.value
        })
    
    def close(self):
        if not self.stop_event.is_set():
            logger.info(f"Client terminated : {self.username}")
            self.stop_event.set()
            self.socket.close()
            self.server.clients.pop(self.username)


class Server:

    def __init__(self, sock: socket.socket) -> None:
        self.clients: Dict[str, ClientHandler] = {}
        self.server_sock = sock
        self.stop_event = threading.Event() # TODO

    def loop(self):
        logger.info("Server started")

        self.db = Db(DATABASE)
        self.db.db_init()
        logger.info("Debugger initialised")

        try:
            for client_socket, client_address in sock_accept(self.server_sock):
                if self.stop_event.is_set():
                    break
                
                # TODO: non blocking accept
                client_socket.setblocking(False)
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
            traceback.print_exc()
            pass

    def close(self):
        self.stop_event.set()
        for client in list(self.clients.values()):
            client.close()
        
        self.clients.clear()
        self.server_sock.close()

def create_server(host: str, port: int):
    logger.info(f"Setting up for hosting at {host}:{port}")

    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setblocking(False)
    s.bind((host, port))
    s.listen(5)

    server = Server(s)

    # Server thread
    t = threading.Thread(target=server.loop)
    t.daemon = True
    t.start()

    return server


def main():
    HOST = socket.gethostbyname(socket.gethostname())
    PORT = 6777
    server = create_server(HOST, PORT)

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