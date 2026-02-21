import logging
import selectors
import socket
import types
import libproxy
from connection_manager import C_Mag
import time

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
}

upstream_rutes = {
    "/app": ("127.0.0.1", 8080),
    "/app/": ("127.0.0.1", 8080),
    "/api/chirps": ("127.0.0.1", 8081),
    "/api/chirps/": ("127.0.0.1", 8081),
}

upstream_status = {
    ("127.0.0.1", 8080): types.SimpleNamespace(status=True, checked=time.time()),
    ("127.0.0.1", 8081): types.SimpleNamespace(status=True, checked=time.time()),
}


def handle_accept(socket):
    conn, addr = socket.accept()
    logger.info("Connection accepted")
    conn.setblocking(False)
    print(f"Client conection to proxy established for: {addr}")
    # "127.0.0.1:8080" - should be removed
    data = libproxy.Message(
        conn,
        selector,
        "127.0.0.1:8080",
        c_mag,
        upstream_rutes,
        upstream_status,
        buckets,
    )
    event = selectors.EVENT_READ
    selector.register(conn, event, data=data)


def check_health(curr_time):
    for k, v in upstream_status.items():
        diff = curr_time - v.checked
        if diff > 10:
            send_health_check(k)


def recv_health_status(key, mask):
    sock = key.fileobj
    conn_data = key.data
    data = sock.recv(4096)
    if data:
        conn_data.inb += data
        if b"\r\n\r\n" in conn_data.inb:
            status = b"200" in conn_data.inb
            # print(f"response to health check from server {key.data.addr} is {key.data}")
            # print(f"status is: {status}")
            upstream_status[conn_data.addr].status = status
            upstream_status[conn_data.addr].checked = time.time()
        print(f"Upstream status: {upstream_status}")


def send_health_check(addr):
    print(f"Checking health for server: {addr}")
    msg = b"HEAD /health HTTP/1.1\r\nHost:127.0.0.1\r\n\r\n"
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        data = types.SimpleNamespace(addr=addr, inb=b"")
        selector.register(conn, selectors.EVENT_READ, data=data)
        conn.connect(addr)
        conn.setblocking(False)
        conn.sendall(msg)
    except ConnectionRefusedError as e:
        print("Unable to connect to server, server is unhealthy")
        upstream_status[addr].status = False
        upstream_status[addr].checked = time.time()


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
        curr_time = time.time()
        check_health(curr_time)
        c_mag.reap_connections()
        events = selector.select(1)
        if events:
            for key, mask in events:
                if key.data is None:
                    handle_accept(key.fileobj)
                elif isinstance(key.data, libproxy.Message):
                    key.data.handle_connection(mask)
                else:
                    recv_health_status(key, mask)
except Exception as e:
    selector.unregister(sock)
    sock.close()
    print(e)
