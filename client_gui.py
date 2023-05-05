from dataclasses import dataclass
import PySimpleGUI as sg
import threading
from typing import *
from client import *

ip = "192.168.1.190"
port = 6777

sg.theme('DarkAmber')  # Add a touch of color
# All the stuff inside your window.

layout = [
    [sg.Text(size=(20, 1), key="current_info")],
    [
        sg.Frame("Conversations",
                 [[sg.Column([[]], key="open_conversations")], [sg.Input(key="n_user")], [sg.Button("Negotiate")]]),
        sg.Column([
            [sg.Multiline(size=(50, 10), key="output", disabled=True)],
            [sg.Text('Message:'), sg.InputText(key="message", do_not_clear=False),
             sg.Button('Send', bind_return_key=True)],
        ])
    ],
    # [sg.Multiline(size=(50, 10), key="log", disabled=True)]
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


class GuiClient:
    def __init__(self):
        r = get_server()
        if r is not None:
            self.ip, self.port, self.username = r
        else:
            exit(0)

        self.client = Client(self.username)
        self.client.connect(self.ip, self.port)
        self.thread = threading.Thread(target=self.client.socket_handler)
        self.thread.daemon = True
        self.thread.start()
        
        print("Client opened.")

        self.window = sg.Window("Chat App", layout)
        self.window.finalize()

        self.currently_messaging: Optional[str] = None
        self.open_conversations: List[str] = []
        self.regen_conversation_list()
        self.window["current_info"].update(f"Currenty logged in as {self.username}")

        self.capture_event(ClientEvent.NEW_CONVERSATION, self.on_new_conversation)
        self.capture_event(ClientEvent.ON_MESSAGE, self.on_message)
        self.capture_event(ClientEvent.ON_CLOSE, self.on_close)
    
    def capture_event(self, event_type: ClientEvent, handler: Callable):
        self.client.register_handler(
            event_type,
            lambda *args, **kwargs: self.window.write_event_value(
                event_type,
                lambda: handler(*args, **kwargs)
            )
        )
    
    def request_gui_update(self, updater_func: Callable):
        self.gui_update_queue.put(updater_func)

    def negotiate_key(self, other_username: str):
        self.client.request_prekey_bundle(other_username)
    
    def reload_conversation(self):
        self.window["output"].update("")
        if self.currently_messaging is not None:
            conv = self.client.find_conversation_by_username(self.currently_messaging)
            if conv is not None:
                for message in conv.messages:
                    self.add_message(message)

    def regen_conversation_list(self):
        def open_conv(name: str):
            self.currently_messaging = name
            self.reload_conversation()

        new_layout = [
            [
                sg.Radio(
                    conv.username,
                    "open_conversation_btns",
                    enable_events=True,
                    key=lambda: open_conv(conv.username)
                )
            ]
            for conv in self.client.session.conversations
        ]
        
        self.window.extend_layout(self.window["open_conversations"], new_layout)
    
    def add_message(self, message: Message):
        # TODO: display time
        self.window["output"].print(f"<{message.user_from}> {message.message}")
    
    def on_message(self, conv: Conversation, message: Message):
        if self.currently_messaging == conv.username:
            self.add_message(message)
    
    def on_new_conversation(self, conv: Conversation):
        self.regen_conversation_list()
    
    def on_close(self):
        self.window.close()

    def mainloop(self):
        while True:
            event, values = self.window.read()

            # Client events
            if isinstance(event, ClientEvent):
                values[event]()


            if event == sg.WIN_CLOSED or event == 'Cancel':  # if user closes window or clicks cancel
                print(values)
                break
            if event == "Negotiate":
                self.negotiate_key(values["n_user"])
            if event == "Send":
                if self.currently_messaging is not None:
                    self.client.send_message(self.currently_messaging, values["message"])

            if callable(event):
                event()

        self.window.close()


c = GuiClient()
c.mainloop()

