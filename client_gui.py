import PySimpleGUI as sg
import socket
import threading
import json
import os
import dh
from typing import *

ip = "192.168.48.1"
port = 6777

sg.theme('DarkAmber')   # Add a touch of color
# All the stuff inside your window.

layout = [
    [sg.Text(size=(20, 1), key="current_info")],
    [
        sg.Frame("Conversations", [[sg.Column([[]], key="open_conversations")], [sg.Input(key="n_user")], [sg.Button("Negotiate")]]),
        sg.Column([
            [sg.Multiline(size=(50, 10), key="output", disabled=True)],
            [sg.Text('Message:'), sg.InputText(key="message", do_not_clear=False), sg.Button('Send', bind_return_key=True)],
        ])
    ],
    #[sg.Multiline(size=(50, 10), key="log", disabled=True)]
]

def get_server():
    layout = [
        [sg.Text("Connect to a server")],
        [sg.Text("Address", size=(8, 1)), sg.Input(ip, key="addr")],
        [sg.Text("Port", size=(8, 1)), sg.Input(port, key="port")],
        [sg.Text("Username", size=(8, 1)), sg.Input(key="username")],
        [sg.Button("Submit")]
    ]
    window = sg.Window("Connect", layout)
    choice = None
    while True:
        event, values = window.read()
        if event == "Submit":
            window.close()
            return values["addr"], int(values["port"]), values["username"]
        
        elif event == sg.WIN_CLOSED:
            break
        
    window.close()

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

class Client:
    def __init__(self):
        r = get_server()
        if r is not None:
            self.ip, self.port, self.username = r
        else:
            exit(0)
        
        self.DATA_FILE = f"{self.username}_keys.json"
        
        self.window = sg.Window("Chat App", layout)
        self.window.finalize()
        
        self.key_data: Dict[str, Any] = {}
        self.sock = self.open_client()
        self.currently_messaging: Optional[str] = None
        self.open_conversations: List[str] = list(self.key_data["negotiations"].keys())
        self.regen_name_list()
        self.window["current_info"].update(f"Currenty logged in as {self.username}")
        

    def open_client(self) -> socket.socket:

        try:
            with open(self.DATA_FILE, "r") as f:
                self.key_data = json.load(f)
                print("Loaded existing key.")
        except (OSError, json.JSONDecodeError) as e:
            print(e)
            me = dh.DiffieHellman()
            self.key_data = {
                "mine": me.save(),
                "negotiations": {}
            }

        me = dh.DiffieHellman.load(self.key_data["mine"])

        with open(self.DATA_FILE, "w") as f:
            json.dump(self.key_data, f, indent=2)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))
        sock.sendall(enc_json({
            "type": "client_init",
            "username": self.username,
            "public_key": me.gen_public_key()
        }))

        print("Connected.")

        stop_event = threading.Event()

        def listener():
            try:
                while not stop_event.is_set():
                    data = dec_json(recv_all(sock))
                    output = self.window["output"]
                    if data["type"] == "message_forward":
                        print(f"<{data['name']}> {data['message']}")
                        output.print(f"<{data['name']}> {data['message']}")
                    
                    elif data["type"] == "user_connect":
                        print(f"[+] {data['name']} has connected.")
                    
                    elif data["type"] == "user_disconnect":
                        #if self.currently_messaging == data["name"]:
                        #    self.currently_messaging = None
                        
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

                        self.key_data["negotiations"][other_name] = {"public_key": data["public_key"]}

                        if other_name not in self.open_conversations:
                            self.open_conversations.append(other_name)
                            self.regen_name_list()
                    
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

        return sock
    
    def negotiate_key(self, other_username: str):
        self.sock.sendall(enc_json({
            "type": "conversation_request",
            "name": other_username
        }))
    
    def regen_name_list(self):
        def open_conv(name):
            self.currently_messaging = name
            self.window["output"].update("")
        
        new_layout = [[sg.Radio(name, "open_conversation_btns", enable_events=True, key=lambda: open_conv(name))] for name in self.open_conversations]
        self.window.extend_layout(self.window["open_conversations"], new_layout)

    
    def mainloop(self):
        while True:
            event, values = self.window.read()
            if event == sg.WIN_CLOSED or event == 'Cancel': # if user closes window or clicks cancel
                break
            if event == "Negotiate":
                self.negotiate_key(values["n_user"])
            if event == "Send":
                if self.currently_messaging is not None:
                    # TODO: send to correct person
                    self.window["output"].print(f"<{self.username}> {values['message']}")
                    self.sock.sendall(enc_json({
                        "type": "message",
                        "name": self.currently_messaging,
                        "message": values["message"]
                    }))
            
            if callable(event):
                event()

        self.window.close()
        
        with open(self.DATA_FILE, "w") as f:
            json.dump(self.key_data, f, indent=2)


c = Client()
c.mainloop()