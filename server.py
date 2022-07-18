import socket
import threading
import socketserver
import time
from typing import *
from dataclasses import dataclass

@dataclass
class Client:
    thread: threading.Thread
    username: str

def try_send(sock: socket.socket, data) -> bool:
    try:
        sock.send(data)
        return True
    except Exception as e:
        print(f"Exception whilst trying to send: {e}")
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
    def __init__(self, sock: socket.socket) -> None:
        self.clients: Dict[socket.socket, Client] = {}
        self.server_sock = sock
    
    def client_link(self, sock: socket.socket, stop_event: threading.Event):
        """Loop for communicating with a client"""
        while not stop_event.is_set():
            try:
                message = recv_all(sock)
            except Exception as e:
                print(f"[!] Error: {e}")
                self.disconnect(sock)
                break

            client = self.clients[sock]
            self.send_to_all(f"<{client.username}> {message.decode('utf-8')}".encode('utf-8'))
    
    def disconnect(self, sock: socket.socket):
        client = self.clients[sock]
        del self.clients[sock]
        self.send_to_all(f"[-] {client.username} has disconnected.".encode("utf-8"))

    def send_to_all(self, data):
        for s in list(self.clients.keys()):
            success = try_send(s, data)
            if not success:
                self.disconnect(s)
    
    def list_users(self) -> List[str]:
        return [c.username for c in self.clients.values()]
    
    def loop(self, stop_event: threading.Event):
        print("Server started")
        try:
            while not stop_event.is_set():
                client_socket, client_address = self.server_sock.accept()
                username = recv_all(client_socket).decode("utf-8")
                print(f"[+] {username} @ {client_address[0]}:{client_address[1]} connected.")
                self.send_to_all(f"[+] {username} has connected.".encode("utf-8"))
                client_socket.send(f"Users connected: {', '.join(self.list_users())}".encode("utf-8"))
                t = threading.Thread(target=self.client_link, args=(client_socket, stop_event))
                self.clients[client_socket] = Client(t, username)
                t.daemon = True
                t.start()
        except Exception as e:
            print(f"Error on server thread: {e}")
            pass
    
    def close(self):
        self.send_to_all("Server closed.".encode("utf-8"))
        for s in list(self.clients.keys()):
            client = self.clients[s]
            s.close()
            client.thread.join()
        
        self.server_sock.close()
        self.clients.clear()

def main():
    HOST, PORT = "localhost", 6777
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
        print("Exiting...")
        pass

    stop_event.set()
    server.close()

if __name__ == "__main__":
    main()
