import socket
import threading


def recvUntil(s, suffix):
    suffix = suffix.encode() if isinstance(suffix, str) else suffix
    ret = b''
    while True:
        c = s.recv(1)
        ret += c
        if ret.endswith(suffix):
            break
    return ret


def recvLine(s):
    return recvUntil(s, '\n')


def sendLine(s, buf):
    buf = buf.encode() if isinstance(buf, str) else buf
    return s.sendall(buf + b'\n')


def listen_on_port(port, handler):
    with socket.create_server(('', port)) as sock:
        while True:
            conn, addr = sock.accept()
            threading.Thread(target=handler, args=(conn, addr,)).start()


def connect_to(port, handler):
    with socket.create_connection(('localhost', port)) as sock:
        ret = handler(sock)
    return ret
