import PySimpleGUI as sg
import socket
import threading
import socketserver

ip = "127.0.0.1"
port = 6777

sg.theme('DarkAmber')   # Add a touch of color
# All the stuff inside your window.
layout = [  [sg.Multiline(size=(100, 20), key="output", disabled=True)],
            [sg.Text("Username:"), sg.InputText(key="username"), sg.Button("Connect")],
            [sg.Text('Message'), sg.InputText(key="message", do_not_clear=False), sg.Button('Send', bind_return_key=True)],
            ]



# Create the Window
window = sg.Window('Chat App', layout)

def recv_all(sock: socket.socket, block_size: int = 1024) -> bytes:
        data = b""
        while True:
            new = sock.recv(block_size)
            data += new
            if len(new) < block_size:
                break
        
        return data

def client(ip: str, port: int, username: str):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    sock.send(bytes(username, 'utf-8'))

    window["output"].print("Connected.")

    stop_event = threading.Event()
    
    def listener():
        try:
            while not stop_event.is_set():
                message = str(recv_all(sock), "utf-8")
                window["output"].print(message)
        except Exception as e:
            print(e)
            if stop_event.is_set():
                window["output"].print("Disconnected, closing...")
            else:
                window["output"].print("Lost connection, closing...")
            stop_event.set()
    
    t = threading.Thread(target=listener)
    t.daemon = True
    t.start()

    return sock

# Event Loop to process "events" and get the "values" of the inputs
sock = None
while True:
    event, values = window.read()
    if event == sg.WIN_CLOSED or event == 'Cancel': # if user closes window or clicks cancel
        break
    if event == "Connect" and sock == None:
        window["output"].update("")
        sock = client(ip, port, values["username"])
    if event == "Send":
        if sock != None:
            sock.send(values["message"].encode("utf-8"))

window.close()