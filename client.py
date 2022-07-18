import socket
import threading
import socketserver
from tracemalloc import stop

def recv_all(sock: socket.socket, block_size: int = 1024) -> bytes:
        data = b""
        while True:
            new = sock.recv(block_size)
            data += new
            if len(new) < block_size:
                break
        
        return data

def client(ip: str, port: int, username: str):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((ip, port))
        sock.send(bytes(username, 'utf-8'))

        print("Connected.")

        stop_event = threading.Event()
        
        def listener():
            try:
                while not stop_event.is_set():
                    message = str(recv_all(sock), "utf-8")
                    print(message)
            except Exception as e:
                stop_event.set()
        
        t = threading.Thread(target=listener)
        t.daemon = True
        t.start()

        try:
            while not stop_event.is_set():
                message = input("")
                sock.sendall(bytes(message, 'utf-8'))
        except KeyboardInterrupt:
            stop_event.set()


ip = "127.0.0.1"
port = 6777

client(ip, port, input("Username: "))
#client(ip, port, "Hello World 2")
#client(ip, port, "Hello World 3")