import selectors
import socket
import types
import libproxy
from connection_manager import C_Mag
import time

selector = selectors.DefaultSelector()
# TODO make configurable
host = "127.0.0.1"
port = 8181


def handle_accept(socket):
    conn, addr = socket.accept()
    conn.setblocking(False)
    print(f"Client conection to proxy established for: {addr}")
    data = libproxy.Message(conn, selector, "127.0.0.1:8080", c_mag)
    event = selectors.EVENT_READ
    selector.register(conn, event, data=data)


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((host, port))
sock.listen()
sock.setblocking(False)
selector.register(sock, selectors.EVENT_READ, data=None)
c_mag = C_Mag(selector)
print(f"Proxy listening on port {port}")

try:
    while True:
        # time.sleep(1)
        c_mag.reap_connections()
        events = selector.select(1)
        if events:
            for key, mask in events:
                if key.data is None:
                    handle_accept(key.fileobj)
                else:
                    key.data.handle_connection(mask)
except Exception as e:
    selector.unregister(sock)
    sock.close()
    print(e)
