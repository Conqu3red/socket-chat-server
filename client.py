import socket
import threading
import json
import os
import dh

def enc_json(data) -> bytes:
    return json.dumps(data).encode("utf-8")


def dec_json(data: bytes):
    print(f"data: {data.decode('utf-8')}")
    return json.loads(data.decode("utf-8"))

def recv_all(sock: socket.socket, block_size: int = 1024) -> bytes:
    data = b""
    while True:
        new = sock.recv(block_size)
        data += new
        if len(new) < block_size:
            break

    return data


def client(ip: str, port: int, username: str):
    DATA_FILE = f"{username}_keys.json"

    try:
        with open(DATA_FILE, "r") as f:
            key_data = json.load(f)
            print("Loaded existing key.")
    except (OSError, json.JSONDecodeError) as e:
        print(e)
        me = dh.DiffieHellman()
        key_data = {
            "mine": me.save(),
            "negotiations": []
        }

    me = dh.DiffieHellman.load(key_data["mine"])

    with open(DATA_FILE, "w") as f:
        json.dump(key_data, f, indent=2)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((ip, port))
        sock.send(enc_json({
            "type": "client_init",
            "username": username,
            "public_key": me.gen_public_key()
        }))

        print("Connected.")

        stop_event = threading.Event()

        def listener():
            try:
                while not stop_event.is_set():
                    data = dec_json(recv_all(sock))
                    if data["type"] == "message_forward":
                        print(f"<{data['name']}> {data['message']}\n")
                    elif data["type"] == "user_connect":
                        print(f"[+] {data['name']} has connected.")
                    elif data["type"] == "user_disconnect":
                        print(f"[-] {data['name']} has disconnected.")
                    elif data["type"] == "server_close":
                        print(f"Server closed.")
                    elif data["type"] == "user_list":
                        print(f"Users connected: {data['users']}")
                    elif data["type"] == "disconnect":
                        print(f"Disconnected from server, reason: {data['reason']}")
                    elif data["type"] == "conversation_init":
                        print(f"conversation {data}")
                        other_name = data["name"]
                        other_public_key = data["public_key"]
                        shared_key = me.gen_shared_key(other_public_key)
                        print(f"Shared key: {shared_key}")
                    else:
                        print(f"Unimplemented message type {data['type']}")

            except Exception as e:
                print("err", repr(e))
                if stop_event.is_set():
                    print("Disconnected, closing...")
                else:
                    print("Lost connection, closing...")
                stop_event.set()

        t = threading.Thread(target=listener)
        t.daemon = True
        t.start()

        target = input("Who to message?")
        sock.sendall(enc_json({
            "type": "conversation_request",
            "name": target
        }))

        try:
            while not stop_event.is_set():
                message = input("")
                sock.sendall(enc_json({
                    "type": "message",
                    "message": message
                }))
        except KeyboardInterrupt:
            stop_event.set()
            sock.close()
        except:
            pass

my_server = True

if my_server:
    ip = "172.16.44.141"
    port = 6777
else:
    ip = "172.16.55.127"
    port = 55555

# my server: 172.16.44.141
# riley's server: 172.16.55.127
#ip = "172.16.44.141" #socket.gethostbyname(socket.gethostname()) #"127.0.0.1"
#port = 55555 #6777

client(ip, port, input("Username: "))