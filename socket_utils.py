import socket
import json
import logging
import select


logger = logging.getLogger('socket')


class ClosedSocket(Exception):
    pass


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
            select.select([], [sock], []) # TODO: timeout
    
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
            select.select([sock], [], [])
    
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
            select.select([sock], [sock], [])
