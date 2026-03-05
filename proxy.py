import logging
import traceback
import selectors
import socket
import types
from health_check import Health_Check

# import libproxy
from connection_manager import Connection_Manager
import time


def handle_accept(socket):
    conn, addr = socket.accept()
    logger.info("Connection accepted")
    conn.setblocking(False)
    print(f"Client conection to proxy established for: {addr}")
    data = Connection_Manager(selector, conn, upstream_status, buckets)
    connection_managers.append(data)
    event = selectors.EVENT_READ
    selector.register(conn, event, data=data)


logging.basicConfig(filename="./proxy.log", level=logging.INFO)

selector = selectors.DefaultSelector()
# TODO make configurable
host = "127.0.0.1"
port = 8181
logger = logging.getLogger(__name__)

buckets = {
    0.02: 0,
    0.05: 0,
    0.1: 0,
    0.2: 0,
    0.5: 0,
    1: 0,
    10: 0,
}

upstream_status = {
    ("127.0.0.1", 8080): types.SimpleNamespace(status=True, checked=time.time()),
    ("127.0.0.1", 8081): types.SimpleNamespace(status=True, checked=time.time()),
}

connection_managers = []


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen()
    sock.setblocking(False)
    selector.register(sock, selectors.EVENT_READ, data=None)
    print(f"Proxy listening on port {port}")
    hc = Health_Check(upstream_status, selector)

    try:
        while True:
            for c in connection_managers[:]:
                c.reap()
                if not c.connection_activity:
                    connection_managers.remove(c)
            events = selector.select(0.1)
            hc.open_connections()
            if events:
                for key, mask in events:
                    if key.data is None:
                        handle_accept(key.fileobj)
                    elif isinstance(key.data, Connection_Manager):
                        key.data.handle_connections(key, mask)
                    else:
                        hc.handle_connections(key, mask)
                        hc.reap()
    except Exception as e:
        selector.unregister(sock)
        sock.close()
        print(f"An error in the main loop occured {e}")
        print(traceback.print_exc())


if __name__ == "__main__":
    main()
